// src/engine.ts — universal decompilation engine.
//
// Pipeline:  sniff magic bytes  →  classify format  →  pick the best available
// decompiler (jadx / ilspycmd / objdump / wabt / bundled fallbacks)  →  collect
// decompiled source or disassembly into a single result document.

import { promises as fs, createReadStream } from 'node:fs'
import * as path from 'node:path'
import * as zlib from 'node:zlib'
import {
  ProvisionError, ensureJadx, ensureIlspycmd, ensureWabt, ensureJava,
  javaEnv, listZipEntries, loadWabt, resolveExe, run, unzip,
} from './toolchain.js'

export interface EngineConfig {
  cacheDir: string
  autoDownload: boolean
  commandTimeoutMs: number
  maxOutputChars: number
  keepWorkspace: boolean
}

export interface EngineDeps {
  signal?: AbortSignal
  /** Called with human-readable progress lines while the engine works. */
  log?: (line: string) => void
  /** Creates the working directory; defaults to fs.mkdtemp with suffix under os.tmpdir(). */
  tempDir?: (prefix: string) => Promise<string>
}

/** JSON-compatible value (avoids importing the harness JsonValue type into the engine). */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

export interface DecompileResult {
  format: string
  engine: string
  summary: string
  /** Primary decompiled/dumped output, already truncated to maxOutputChars. */
  code: string
  /** Paths of every extracted source file (when a multi-file decompiler ran). */
  files: string[]
  /** Machine-readable facts about the input file. */
  info: Record<string, Json>
  /** Non-fatal warnings and skipped-stage notes. */
  warnings: string[]
  /** Absolute path of the analyzed file. */
  source: string
  /** Whether a real decompiler/disassembler produced the output. */
  ok: boolean
}

interface Stage {
  ok: boolean
  engine: string
  summary: string
  code?: string
  files?: string[]
  warnings?: string[]
}

const buf = (f: string, n: number, off = 0): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    const stream = createReadStream(f, { start: off, end: off + n - 1 })
    const chunks: Buffer[] = []
    stream.on('data', (c) => { chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)) })
    stream.on('error', reject)
    stream.on('end', () => resolve(Buffer.concat(chunks)))
  })

const hex = (b: Buffer) => b.toString('hex').toUpperCase().match(/../g)?.join(' ') ?? ''

async function classify(filePath: string): Promise<{ magic: string; format: string; engine: string } | null> {
  const head = await buf(filePath, 4096)
  const match = (offset: number, ...candidates: Buffer[]) => candidates.some((c) => head.subarray(offset, offset + c.length).equals(c))
  const ascii8 = head.subarray(0, 8)

  if (match(0, Buffer.from('PK\x03\x04')) || match(0, Buffer.from('PK\x05\x06'))) {
    const names = await listZipEntriesSafe(filePath)
    if (names.some((n) => n === 'AndroidManifest.xml' || n.startsWith('META-INF/') && n.endsWith('.SF')) && names.some((n) => n.endsWith('.dex'))) {
      return { magic: 'PK.. AndroidManifest.xml + classes*.dex', format: 'android/apk', engine: 'jadx' }
    }
    if (names.some((n) => /^classes\d*\.dex$/.test(n))) return { magic: 'PK.. classes*.dex', format: 'android/apk', engine: 'jadx' }
    if (names.some((n) => n.endsWith('.dex'))) return { magic: 'PK.. *.dex', format: 'android/apk', engine: 'jadx' }
    if (names.some((n) => /^[Bb]in\/[^/]+\.(exe|dll)$/i.test(n)) || names.some((n) => /^lib\/[^/]+\/[^/]+\.so$/.test(n))) {
      return { magic: 'PK.. bin/*.exe | lib/*/*.so', format: 'archive', engine: 'archive' }
    }
    if (names.some((n) => /\.(class|jar)$/.test(n))) return { magic: 'PK.. *.class | *.jar', format: 'jvm/archive', engine: 'archive' }
    return { magic: 'PK\x03\x04', format: 'archive', engine: 'archive' }
  }
  if (match(0, Buffer.from('dex\n'))) return { magic: 'dex\n035\0 (or 036/037/038)', format: 'android/dex', engine: 'jadx' }
  if (match(0, Buffer.from('\xca\xfe\xba\xbe'))) {
    // could be a Java class or a Mach-O fat binary
    const isMacho = head.length >= 8 && (head.readUInt32BE(4) === 0xfeedface || head.readUInt32BE(4) === 0xfeedfacf || (head.readUInt32BE(4) & 0xFFFFFF00) === 0xcafe0000 && head.readUInt32BE(4) !== 0xcafebabe)
    if (isMacho) return { magic: 'cafebabe (Mach-O fat)', format: 'mach-o', engine: 'objdump' }
    return { magic: 'cafebabe', format: 'jvm/class', engine: 'jadx' }
  }
  if (match(0, Buffer.from('\x7fELF')) && (head[4] === 1 || head[4] === 2)) return { magic: `7f454c46 EI_CLASS=${head[4] === 2 ? '64' : '32'}`, format: 'elf', engine: 'objdump' }
  if (match(0, Buffer.from('MZ'))) {
    const isDotNet = await detectDotNetPe(head, filePath)
    return { magic: '4d5a (MZ)' + (isDotNet ? ' + CLI header' : ''), format: isDotNet ? 'pe/dotnet' : 'pe', engine: isDotNet ? 'ilspycmd' : 'objdump' }
  }
  if (match(0, Buffer.from('\0asm')) || match(0, Buffer.from('asm\0'))) return { magic: '00 61 73 6d (\\0asm)', format: 'wasm', engine: 'wasm2wat' }
  if (match(0, Buffer.from('\xce\xfa\xed\xfe')) || match(0, Buffer.from('\xcf\xfa\xed\xfe')) || match(0, Buffer.from('\xfe\xed\xfa\xce')) || match(0, Buffer.from('\xfe\xed\xfa\xcf'))) {
    return { magic: 'feedface / feedfacf', format: 'mach-o', engine: 'objdump' }
  }
  if (match(257, Buffer.from('ustar')) || match(257, Buffer.from('ustar  \0'))) return { magic: 'ustar @257', format: 'tar', engine: 'archive' }
  if (match(0, Buffer.from('7z\xbc\xaf\x27\x1c'))) return { magic: '37 7A BC AF 27 1C', format: '7z', engine: 'archive' }
  if (match(0, Buffer.from('\x1f\x8b'))) return { magic: '1f 8b (gzip)', format: 'gzip', engine: 'archive' }
  if (match(0, Buffer.from('BM')) && head.length >= 6) return { magic: '424d (BM)', format: 'image', engine: 'none' }
  if (match(0, Buffer.from('%PDF'))) return { magic: '25504446 (%PDF)', format: 'pdf', engine: 'none' }
  if (ascii8.length >= 8 && /^(?:#!|<\?xml|<html)/i.test(ascii8.toString('latin1').replace(/\0+$/, ''))) {
    return { magic: `shebang/xml: ${ascii8.subarray(0, 4).toString('hex').toUpperCase()}`, format: 'text', engine: 'none' }
  }
  return null
}

async function listZipEntriesSafe(zipPath: string): Promise<string[]> {
  try {
    return await listZipEntries(zipPath)
  } catch {
    return []
  }
}

/**
 * A PE is a .NET assembly when its second data directory (index 14, offset
 * 0xE8 for PE32+) points to a CLI header whose major version is >= 2.
 */
async function detectDotNetPe(head: Buffer, filePath: string): Promise<boolean> {
  try {
    const peOff = head.readUInt32LE(0x3c)
    if (peOff < 0x40 || peOff + 24 > head.length || head.readUInt32LE(peOff) !== 0x00004550) return false
    const magic = head.readUInt16LE(peOff + 24)
    const is64 = magic === 0x20b
    const optHdrSize = head.readUInt16LE(peOff + 20)
    const dataDirOffset = is64 ? peOff + 24 + 112 : peOff + 24 + 96
    if (dataDirOffset + 16 > head.length || dataDirOffset + 16 > peOff + 24 + optHdrSize) return false
    const cliRva = head.readUInt32LE(dataDirOffset + 14 * 8)
    const cliSize = head.readUInt32LE(dataDirOffset + 14 * 8 + 4)
    if (!cliRva || !cliSize || cliSize < 4) return false
    const fade = await rvaToOffset(filePath, cliRva, head)
    const cli = fade ? await buf(filePath, 4, fade) : Buffer.alloc(0)
    return cli.length >= 4 && (cli.readUInt16LE(0) >= 2)
  } catch {
    return false
  }
}

/** Convert an RVA to a file offset using the section table (PE32/PE32+). */
async function rvaToOffset(filePath: string, rva: number, head: Buffer): Promise<number | null> {
  let h = head
  const peOff = h.readUInt32LE(0x3c)
  const numSections = h.readUInt16LE(peOff + 6)
  const optHdrSize = h.readUInt16LE(peOff + 20)
  const sectionsOffset = peOff + 24 + optHdrSize
  if (sectionsOffset + numSections * 40 > h.length) h = await buf(filePath, Math.max(4096, sectionsOffset + numSections * 40))
  const magic = h.readUInt16LE(peOff + 24)
  const is64 = magic === 0x20b
  const imageBaseOffset = is64 ? peOff + 24 + 24 : peOff + 24 + 28
  const imageBase = is64 ? Number(h.readBigUInt64LE(imageBaseOffset)) : h.readUInt32LE(imageBaseOffset)
  void imageBase
  const mapped = rva
  for (let i = 0; i < numSections; i++) {
    const s = sectionsOffset + i * 40
    const vaddr = h.readUInt32LE(s + 12)
    const vsize = h.readUInt32LE(s + 8)
    const rawPtr = h.readUInt32LE(s + 20)
    if (mapped >= vaddr && mapped < vaddr + Math.max(vsize, 1)) {
      return rawPtr + (mapped - vaddr)
    }
  }
  return null
}

function escapeForSummary(s: string): string {
  return s.replace(/[\r\n]+/g, ' ').slice(0, 120)
}

/**
 * The universal entry point: classify the file and run every stage that can
 * contribute decompiled output, in priority order, until one succeeds.
 */
export async function decompile(filePath: string, config: EngineConfig, deps: EngineDeps = {}): Promise<DecompileResult> {
  const abs = path.resolve(filePath)
  const stat = await fs.stat(abs).catch(() => null)
  if (!stat || !stat.isFile()) throw new ProvisionError(`file not found or not a regular file: ${abs}`)
  const log = deps.log ?? (() => {})
  const warnings: string[] = []

  const detected = await classify(abs)
  log(`magic sniff: ${detected ? detected.magic : 'unknown'} → ${detected ? `${detected.format}/${detected.engine}` : 'unknown'}`)

  const info: Record<string, Json> = {
    file: abs,
    sizeBytes: stat.size,
    size: formatSize(stat.size),
    ...(detected ? { magic: detected.magic, format: detected.format } : {}),
  }

  const ctx: StageContext = {
    abs, config, deps, log, warnings, tempDir: deps.tempDir ?? (() => fs.mkdtemp(path.join(requireOsTmpdir(), 'omni-'))),
    java: undefined, jadx: undefined, ilspycmd: undefined, wabt: undefined, javaResolved: false,
  }

  let format = detected?.format ?? 'unknown'
  let engine = detected?.engine ?? 'unknown'
  let stage: Stage | null = null

  try {
    switch (detected?.engine) {
      case 'jadx': stage = await runJadx(ctx); break
      case 'ilspycmd': stage = await runIlspy(ctx); break
      case 'objdump': stage = await runObjdumpStage(ctx, detected.format); break
      case 'wasm2wat': stage = await runWasm(ctx); break
      case 'archive': stage = await runArchive(ctx, detected.format); break
      default: /* fall through below */ break
    }
  } catch (err) {
    if (err instanceof ProvisionError && /aborted/.test(err.message)) throw err
    warnings.push(`primary stage failed: ${(err as Error).message}`)
    log(`primary stage failed: ${escapeForSummary((err as Error).message)}`)
    stage = null
  }

  if (!stage?.ok) {
    const fb = await runFallbackDump(ctx, format)
    if (fb.ok) {
      if (stage) warnings.push(...(stage.warnings ?? []), `primary engine (${engine}) unavailable, showing ${fb.engine} output`)
      else warnings.push(`no decompiler mapping for ${format}, showing ${fb.engine} output`)
      format = 'unknown'
      engine = fb.engine
      stage = fb
    } else if (stage) {
      warnings.push(...(stage.warnings ?? []))
    } else {
      stage = {
        ok: false, engine: 'none',
        summary: `no decompiler available for ${format}`,
        code: `Cannot decompile ${path.basename(abs)}: detected ${format} (magic: ${detected ? detected.magic : 'unknown'}) but every decompiler stage failed or produced no output.\nInstall jadx / ilspycmd / objdump / wabt (or enable autoDownload), then retry.\nFile: ${abs} (${formatSize(stat.size)})`,
      }
    }
  }

  const max = Math.max(64, config.maxOutputChars)
  let code = stage.code ?? ''
  if (!stage.ok && code.trim().length === 0) {
    code = `Decompilation produced no output for ${path.basename(abs)} (${format}, ${formatSize(stat.size)}).\n` +
      `Engine errors:\n${dedupe(warnings).map((w) => `- ${w}`).join('\n') || '- none recorded'}\n` +
      `File: ${abs}`
  }
  code = truncate(code, Math.min(max, config.maxOutputChars))
  return {
    format, engine: stage.engine, summary: stage.summary, code,
    files: (stage.files ?? []).filter((f) => typeof f === 'string'),
    info, warnings: dedupe(warnings), source: abs,
    ok: stage.ok && code.length > 0,
  }
}

interface StageContext {
  abs: string
  config: EngineConfig
  deps: EngineDeps
  log: (line: string) => void
  warnings: string[]
  tempDir: (prefix: string) => Promise<string>
  java?: string
  jadx?: string
  ilspycmd?: string | null
  wabt?: { kind: 'native'; bin: string } | { kind: 'npm'; moduleDir: string }
  javaResolved: boolean
}

function requireOsTmpdir(): string {
  const t = process.env.TEMP || process.env.TMP || (process.platform === 'win32' ? 'C:\\Windows\\Temp' : '/tmp')
  return t
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function dedupe(arr: string[]): string[] {
  return [...new Set(arr)]
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text
  const half = Math.floor((max - 200) / 2)
  return `${text.slice(0, Math.max(half, 1))}\n\n… [truncated ${formatSize(text.length - max)} of output; ${formatSize(text.length)} total] …\n\n${text.slice(-half)}`
}

async function collectSources(dir: string): Promise<{ files: string[]; merged: string; totalBytes: number }> {
  const sources: string[] = []
  const walk = async (d: string) => {
    const entries = await fs.readdir(d, { withFileTypes: true }).catch(() => [])
    // sort for deterministic output: directories first, then files alphabetically
    entries.sort((a, b) => (a.isDirectory() === b.isDirectory() ? a.name.localeCompare(b.name) : a.isDirectory() ? -1 : 1))
    for (const e of entries) {
      const full = path.join(d, e.name)
      if (e.isDirectory()) await walk(full)
      else if (/\.(java|kt|smali|cs|c|cc|cpp|h|hpp|s|S|asm|wat|txt|json|xml|py|js|ts|go|rs|rb|php|lua|sh|md|manifest|dex)$/.test(e.name)) sources.push(full)
    }
  }
  await walk(dir)
  sources.sort()
  let total = 0
  const parts: string[] = []
  for (const f of sources) {
    const content = await fs.readFile(f, 'utf8').catch(() => '')
    total += content.length
    if (total > 64 * 1024 * 1024) continue
    parts.push(`// ==== ${path.relative(dir, f).replace(/\\/g, '/')} ==== (${formatSize(content.length)})\n${content}`)
  }
  return { files: sources, merged: parts.join('\n\n'), totalBytes: total }
}

// ---------------------------------------------------------------------------
// Stage: jadx — APK / DEX / JAR / CLASS → Java
// ---------------------------------------------------------------------------

async function runJadx(ctx: StageContext): Promise<Stage> {
  if (!ctx.jadx) {
    const { jadx, java } = await ensureJadx({
      cacheDir: ctx.config.cacheDir, autoDownload: ctx.config.autoDownload,
      timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal,
    })
    ctx.jadx = jadx; ctx.java = java; ctx.javaResolved = true
  }
  if (!ctx.javaResolved) { ctx.java = await ensureJava({ cacheDir: ctx.config.cacheDir, autoDownload: ctx.config.autoDownload, timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal }); ctx.javaResolved = true }
  const outDir = await ctx.tempDir('jadx-')
  const args = ['-d', outDir, '--no-res', '-v', ctx.abs]
  ctx.log(`jadx: spawn ${path.basename(ctx.jadx)} (java=${path.basename(ctx.java ?? 'system')})`)
  const r = await run(ctx.jadx, args, {
    cwd: path.dirname(ctx.jadx), env: javaEnv(ctx.java!), timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal,
  })
  const stderrTail = r.stderr.trim().split(/\r?\n/).slice(-4).join(' | ')
  const collected = await collectSources(outDir)
  if (!collected.merged && !collected.files.length) {
    if (r.timedOut) throw new ProvisionError(`jadx timed out after ${ctx.config.commandTimeoutMs}ms`)
    return {
      ok: false, engine: 'jadx', summary: `jadx exited ${r.exitCode} and produced no sources${stderrTail ? ` — ${stderrTail}` : ''}`,
      code: '', warnings: [`jadx stderr tail: ${stderrTail}`],
    }
  }
  const langs = new Set(collected.files.map((f) => path.extname(f)))
  const classes = collected.files.filter((f) => f.endsWith('.java')).length
  return {
    ok: true, engine: 'jadx', files: collected.files,
    summary: `jadx → ${classes} Java file(s)${langs.has('.kt') ? ' + Kotlin' : ''} · ${formatSize(collected.totalBytes)}${r.exitCode !== 0 ? ` (exit ${r.exitCode})` : ''}`,
    code: collected.merged,
    warnings: r.exitCode !== 0 ? [`jadx exit code ${r.exitCode}; returning partial output`] : [],
  }
}

// ---------------------------------------------------------------------------
// Stage: ilspycmd — .NET assemblies → C#
// ---------------------------------------------------------------------------

async function runIlspy(ctx: StageContext): Promise<Stage> {
  if (ctx.ilspycmd === undefined) {
    ctx.ilspycmd = await ensureIlspycmd({
      cacheDir: ctx.config.cacheDir, autoDownload: ctx.config.autoDownload,
      timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal,
    })
  }
  if (!ctx.ilspycmd) {
    ctx.log('ilspycmd unavailable; falling back to objdump for .NET PE')
    const disasm = await runObjdumpStage(ctx, 'pe/dotnet')
    return {
      ok: disasm.ok, engine: disasm.engine, files: disasm.files,
      summary: disasm.summary.replace(/^objdump/, 'objdump (no ilspycmd)'),
      code: disasm.code, warnings: [...(disasm.warnings ?? []), 'ilspycmd not available: install the .NET SDK and run `dotnet tool install -g ilspycmd`, or enable autoDownload'],
    }
  }
  const outDir = await ctx.tempDir('ilspy-')
  const args = [ctx.abs, '-o', outDir, '-p']
  ctx.log(`ilspycmd: spawn ${path.basename(ctx.ilspycmd)}`)
  const r = await run(ctx.ilspycmd, args, { timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal })
  const collected = await collectSources(outDir)
  if (!collected.merged && !collected.files.length) {
    return {
      ok: false, engine: 'ilspycmd',
      summary: `ilspycmd exited ${r.exitCode}${r.stderr ? ` — ${r.stderr.trim().split(/\r?\n/).pop() ?? ''}` : ''}`,
      code: '', warnings: [`ilspycmd exit code ${r.exitCode}`],
    }
  }
  return {
    ok: true, engine: 'ilspycmd', files: collected.files,
    summary: `ilspycmd → ${collected.files.length} C# file(s) · ${formatSize(collected.totalBytes)}${r.exitCode !== 0 ? ` (exit ${r.exitCode})` : ''}`,
    code: collected.merged,
    warnings: r.exitCode !== 0 ? [`ilspycmd exit code ${r.exitCode}; returning partial output`] : [],
  }
}

// ---------------------------------------------------------------------------
// Stage: objdump — PE / ELF / Mach-O → disassembly + symbols
// ---------------------------------------------------------------------------

async function runObjdumpStage(ctx: StageContext, format: string): Promise<Stage> {
  const objdump = resolveExe('objdump')
  if (!objdump) {
    const msg = 'objdump not found on PATH; install binutils (or mingw-w64 on Windows)'
    ctx.log(msg)
    return { ok: false, engine: 'objdump', summary: 'objdump unavailable', code: '', warnings: [msg] }
  }
  const note = format === 'elf' ? '(ELF)' : format === 'mach-o' ? '(Mach-O, best effort with GNU objdump)' : '(PE)'
  const sections = await run(objdump, ['-h', ctx.abs], { timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal })
  const symbols = await run(objdump, ['-T', ctx.abs], { timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal }).catch(() => null)
  ctx.log('objdump: disassembling (this may take a while for large binaries)')
  const disasm = await run(objdump, ['-d', '--no-show-raw-insn', ctx.abs], { timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal })
  const parts: string[] = []
  parts.push(`# === ${path.basename(ctx.abs)} — disassembly ${note} ===`)
  if (sections.stdout.trim()) parts.push(`\n# --- sections ---\n${sections.stdout.trim()}`)
  if (symbols && symbols.stdout.trim()) parts.push(`\n# --- dynamic symbols ---\n${symbols.stdout.trim()}`)
  if (disasm.stdout.trim()) parts.push(`\n# --- disassembly ---\n${disasm.stdout.trim()}`)
  if (disasm.stderr.trim()) parts.push(`\n# --- objdump stderr ---\n${disasm.stderr.trim()}`)
  const code = parts.join('\n')
  if (!disasm.stdout.trim() && !sections.stdout.trim()) {
    return {
      ok: false, engine: 'objdump',
      summary: `objdump produced no output (exit ${disasm.exitCode})`,
      code: '', warnings: [`objdump exit code ${disasm.exitCode}: ${disasm.stderr.trim().slice(0, 200)}`],
    }
  }
  return {
    ok: true, engine: 'objdump',
    summary: `objdump → disassembly ${note} · ${formatSize(code.length)}`,
    code,
    warnings: disasm.timedOut ? ['disassembly timed out; partial output returned'] : [],
  }
}

// ---------------------------------------------------------------------------
// Stage: wasm2wat — WebAssembly → WAT text format
// ---------------------------------------------------------------------------

async function runWasm(ctx: StageContext): Promise<Stage> {
  const wabt = ctx.wabt ?? await ensureWabt({
    cacheDir: ctx.config.cacheDir, autoDownload: ctx.config.autoDownload,
    timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal,
  })
  ctx.wabt = wabt
  if (wabt.kind === 'native') {
    ctx.log('wasm2wat: native binary')
    const r = await run(wabt.bin, [ctx.abs], { timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal })
    if (!r.stdout.trim()) {
      return { ok: false, engine: 'wasm2wat', summary: `wasm2wat exited ${r.exitCode}`, code: '', warnings: [`wasm2wat stderr: ${r.stderr.trim().slice(0, 200)}`] }
    }
    return { ok: true, engine: 'wasm2wat', summary: `wasm2wat → ${formatSize(r.stdout.length)} WAT`, code: r.stdout }
  }
  ctx.log('wasm2wat: wabt npm module (auto-installed)')
  const wasm = await fs.readFile(ctx.abs)
  const mod = await loadWabt(wabt.moduleDir)
  const result = mod.readWasm(new Uint8Array(wasm), { exceptions: true, mutable_globals: true, sat_float_to_int: true, sign_extension: true, simd: true, threads: true, multi_value: true, tail_call: true, bulk_memory: true, reference_types: true })
  const wat = result.toText({ fold_exprs: false, inline_export: false })
  return { ok: true, engine: 'wabt(npm)', summary: `wabt → ${formatSize(wat.length)} WAT`, code: wat }
}

// ---------------------------------------------------------------------------
// Stage: archives (zip/apk-resources/tar/7z/gz) → recursive decompile
// ---------------------------------------------------------------------------

async function runArchive(ctx: StageContext, format: string): Promise<Stage> {
  const outDir = await ctx.tempDir('unpack-')
  let entries: string[] = []
  try {
    if (format === 'tar') {
      const tar = ctx.abs
      // tar may be plain or compressed; detect via magic
      const head = await buf(tar, 4)
      if (head.subarray(0, 2).equals(Buffer.from('\x1f\x8b'))) {
        const gzPath = `${tar}.gz`
        await fs.copyFile(tar, gzPath)
        await untarGzInto(gzPath, outDir)
      } else {
        await untarGzInto(tar, outDir, true)
      }
    } else if (format === 'gzip') {
      const gunzipped = zlib.gunzipSync(await fs.readFile(ctx.abs))
      await fs.mkdir(outDir, { recursive: true })
      const inner = path.join(outDir, path.basename(ctx.abs).replace(/\.gz$/, ''))
      await fs.writeFile(inner, gunzipped)
      // recurse into the single decompressed member
      const sub = await decompile(inner, ctx.config, ctx.deps)
      return {
        ok: sub.ok, engine: `gzip>${sub.engine}`, summary: `gzip → ${sub.summary}`, code: sub.code,
        files: sub.files, warnings: sub.warnings,
      }
    } else if (format === '7z') {
      const sevenZ = resolveExe('7z') || resolveExe('7za')
      if (!sevenZ) return { ok: false, engine: '7z', summary: '7z archive but no 7z/7za binary on PATH', code: '', warnings: ['install 7-Zip to unpack .7z archives'] }
      const r = await run(sevenZ, ['x', '-y', `-o${outDir}`, ctx.abs], { timeoutMs: ctx.config.commandTimeoutMs, signal: ctx.deps.signal })
      if (r.exitCode !== 0) return { ok: false, engine: '7z', summary: `7z exited ${r.exitCode}`, code: '', warnings: [r.stderr.slice(0, 200)] }
    } else {
      // plain zip (incl. APK with resources only, jar archives)
      await unzip(ctx.abs, outDir)
    }
  } catch (err) {
    return { ok: false, engine: 'archive', summary: `unpack failed: ${(err as Error).message}`, code: '', warnings: [`unpack: ${(err as Error).message}`] }
  }
  entries = await listDirDeep(outDir)
  const candidates = entries.filter((f) => /\.(dex|apk|jar|class|exe|dll|so|dylib|wasm|zip|tar|gz|7z|aar|war)$/i.test(f))
  ctx.log(`archive unpacked: ${entries.length} entries, ${candidates.length} decompilable candidates`)
  if (!candidates.length) {
    const collected = await collectSources(outDir)
    if (collected.merged) {
      return { ok: true, engine: 'archive', summary: `unpacked ${entries.length} entries`, code: collected.merged, files: collected.files }
    }
    return { ok: true, engine: 'archive', summary: `unpacked ${entries.length} entries (no decompilable payload)`, code: entries.slice(0, 200).map((f) => path.relative(outDir, f)).join('\n') + (entries.length > 200 ? `\n…and ${entries.length - 200} more` : ''), files: entries }
  }
  // decompile the first few candidates (bounded) and concatenate
  const results: string[] = []
  const allWarnings: string[] = []
  const allFiles: string[] = []
  const limit = Math.min(candidates.length, 3)
  for (const candidate of candidates.slice(0, limit)) {
    try {
      const sub = await decompile(candidate, ctx.config, ctx.deps)
      results.push(`\n# ===== ${path.relative(outDir, candidate).replace(/\\/g, '/')} =====\n# ${sub.summary}\n\n${sub.code}`)
      allWarnings.push(...sub.warnings)
      allFiles.push(...sub.files)
    } catch (err) {
      allWarnings.push(`${path.basename(candidate)}: ${(err as Error).message}`)
    }
  }
  if (candidates.length > limit) allWarnings.push(`archive contains ${candidates.length - limit} further decompilable member(s); only the first ${limit} were processed`)
  const merged = results.join('\n')
  return {
    ok: merged.length > 0, engine: 'archive>recurse',
    summary: `unpacked ${entries.length} entries → decompiled ${limit}/${candidates.length}`,
    code: merged, files: allFiles, warnings: allWarnings,
  }
}

async function untarGzInto(tarPath: string, destDir: string, plain = false): Promise<void> {
  const data = plain ? await fs.readFile(tarPath) : zlib.gunzipSync(await fs.readFile(tarPath))
  await fs.mkdir(destDir, { recursive: true })
  let p = 0
  while (p + 512 <= data.length) {
    const h = data.subarray(p, p + 512)
    if (h.every((b) => b === 0)) break
    const name = h.subarray(0, 100).toString('utf8').replace(/\0+$/, '')
    const type = String.fromCharCode(h[156] ?? 0)
    const size = parseInt(h.subarray(124, 136).toString('ascii').replace(/\0+$/, '').trim(), 8) || 0
    p += 512
    const blocks = Math.ceil(size / 512) * 512
    if (type === '0' || type === '\0') {
      const target = path.join(destDir, name)
      if (!path.relative(destDir, path.resolve(target)).startsWith('..')) {
        await fs.mkdir(path.dirname(target), { recursive: true })
        await fs.writeFile(target, data.subarray(p, p + size))
      }
    } else if (type === '5') {
      await fs.mkdir(path.join(destDir, name), { recursive: true })
    }
    p += blocks
  }
}

async function listDirDeep(dir: string): Promise<string[]> {
  const out: string[] = []
  const walk = async (d: string) => {
    const entries = await fs.readdir(d, { withFileTypes: true }).catch(() => [])
    for (const e of entries) {
      const full = path.join(d, e.name)
      if (e.isDirectory()) await walk(full)
      else out.push(full)
    }
  }
  await walk(dir)
  return out
}

// ---------------------------------------------------------------------------
// Fallback strings stage
// ---------------------------------------------------------------------------

async function runFallbackDump(ctx: StageContext, _format: string): Promise<Stage> {
  const strings = resolveExe('strings')
  if (!strings) return { ok: false, engine: 'none', summary: 'no further fallback available', code: '' }
  ctx.log('fallback: running strings')
  const r = await run(strings, ['-n', '6', ctx.abs], { timeoutMs: Math.min(ctx.config.commandTimeoutMs, 120_000), signal: ctx.deps.signal })
  if (!r.stdout.trim()) return { ok: false, engine: 'none', summary: 'strings produced no output', code: '' }
  return {
    ok: true, engine: 'strings',
    summary: `strings → ${formatSize(r.stdout.length)} of printable strings (fallback)`,
    code: `# === ${path.basename(ctx.abs)} — printable strings (fallback; primary decompiler unavailable) ===\n${r.stdout}`,
  }
}

// re-exported for index.ts
export { escapeForSummary, truncate }
export { ProvisionError } from './toolchain.js'
export const ENGINE_VERSION = '0.1.0'
