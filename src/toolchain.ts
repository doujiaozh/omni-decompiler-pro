// src/toolchain.ts — command runner and zero-dependency tool provisioning.
//
// Everything here must work with only Node.js built-ins: spawning external
// decompilers, streaming downloads, extracting .zip (central directory walk)
// and .tar.gz archives, resolving tools from PATH, and auto-provisioning the
// open-source decompilers this engine dispatches to.

import { spawn } from 'node:child_process'
import { createWriteStream, promises as fs, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import * as path from 'node:path'
import * as zlib from 'node:zlib'
import { pathToFileURL } from 'node:url'
import { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'

/** Raised when an external tool cannot be found and cannot be provisioned. */
export class ProvisionError extends Error {}

export interface ToolEnv {
  /** Root directory for downloaded toolchains. */
  cacheDir: string
  /** AbortSignal propagated from the tool execution. */
  signal?: AbortSignal
  /** Per-command budget in milliseconds. */
  timeoutMs?: number
  /** Whether downloading missing tools is allowed. */
  autoDownload: boolean
}

export interface RunOptions {
  cwd?: string
  env?: NodeJS.ProcessEnv
  timeoutMs?: number
  signal?: AbortSignal
  /** Hard cap on captured stdout/stderr; excess is truncated. */
  maxBufferBytes?: number
}

export interface RunResult {
  command: string
  args: string[]
  exitCode: number
  stdout: string
  stderr: string
  durationMs: number
  timedOut: boolean
}

const DEFAULT_MAX_BUFFER = 256 * 1024 * 1024

/** Quote one argument for cmd.exe (used for .bat/.cmd launchers such as jadx). */
function quoteForCmd(s: string): string {
  if (/[\s"^&|<>]/.test(s)) return `"${s.replace(/"/g, '""')}"`
  return s
}

/**
 * Spawn an external command, capture stdout/stderr, and enforce a timeout.
 * On Windows, .bat/.cmd launchers are routed through cmd.exe with manual
 * quoting; a timeout tree-kills the process so JVMs do not survive.
 */
export function run(file: string, args: string[], opts: RunOptions = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    if (opts.signal?.aborted) {
      reject(new ProvisionError('aborted before start'))
      return
    }
    const started = Date.now()
    let cmd = file
    let argv = args
    if (process.platform === 'win32' && /\.(bat|cmd)$/i.test(file)) {
      cmd = process.env.ComSpec || 'cmd.exe'
      argv = ['/c', quoteForCmd(file), ...args.map(quoteForCmd)]
    }
    const max = Math.min(opts.maxBufferBytes ?? DEFAULT_MAX_BUFFER, DEFAULT_MAX_BUFFER)

    const child = spawn(cmd, argv, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    const chunks: Buffer[] = [Buffer.from('')]
    const errChunks: Buffer[] = [Buffer.from('')]
    let captured = 0
    let truncated = false
    let timedOut = false
    let settled = false

    const finish = (exitCode: number) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      opts.signal?.removeEventListener('abort', onAbort)
      resolve({
        command: file,
        args,
        exitCode,
        stdout: Buffer.concat(chunks).toString('utf8'),
        stderr: Buffer.concat(errChunks).toString('utf8'),
        durationMs: Date.now() - started,
        timedOut,
        ...(truncated ? { /* stdout truncated below */ } : {}),
      })
    }

    const timer = setTimeout(() => {
      timedOut = true
      killChild(child)
      finish(-1)
    }, opts.timeoutMs ?? 0)

    const onAbort = () => {
      killChild(child)
      finish(-1)
    }
    opts.signal?.addEventListener('abort', onAbort, { once: true })

    const collect = (target: Buffer[], data: Buffer) => {
      if (captured >= max) {
        truncated = true
        return
      }
      const room = max - captured
      target.push(room >= data.length ? data : data.subarray(0, room))
      captured += Math.min(data.length, room)
      if (captured >= max) truncated = true
    }

    child.stdout?.on('data', (d: Buffer) => collect(chunks, d))
    child.stderr?.on('data', (d: Buffer) => collect(errChunks, d))
    child.on('error', (err) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      opts.signal?.removeEventListener('abort', onAbort)
      reject(new ProvisionError(`failed to spawn ${file}: ${err.message}`))
    })
    child.on('close', (code) => finish(typeof code === 'number' ? code : -1))
  })
}

function killChild(child: ReturnType<typeof spawn>) {
  if (!child.pid) return
  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/F', '/T', '/PID', String(child.pid)], { windowsHide: true, stdio: 'ignore' })
    } else {
      process.kill(child.pid, 'SIGKILL')
    }
  } catch {
    // best effort
  }
  try {
    child.kill('SIGKILL')
  } catch {
    // best effort
  }
}

/** Resolve an executable on PATH (honoring PATHEXT on Windows). */
export function resolveExe(name: string): string | null {
  const exts = process.platform === 'win32'
    ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';').filter(Boolean)
    : ['']
  const withExts = (base: string) => exts.map((e) => base + e)
  const candidates: string[] = []
  if (name.includes(path.posix.sep) || (path.sep === '\\' && name.includes('\\'))) {
    candidates.push(...withExts(path.resolve(name)))
  } else {
    for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
      if (!dir) continue
      candidates.push(...withExts(path.resolve(dir, name)))
    }
  }
  for (const c of candidates) {
    try {
      if (statSync(c).isFile()) return c
    } catch {
      // try next
    }
  }
  return null
}

export function isExecutable(file: string): boolean {
  try {
    return statSync(file).isFile()
  } catch {
    return false
  }
}

/** Stream a URL to disk atomically (writes to .part, then renames), retrying on connection loss. */
export async function downloadFile(
  url: string,
  dest: string,
  opts: { signal?: AbortSignal; timeoutMs?: number; retries?: number } = {},
): Promise<void> {
  const attempts = Math.max(1, opts.retries ?? 4)
  let lastErr: unknown
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await downloadFileOnce(url, dest, opts)
      return
    } catch (err) {
      lastErr = err
      if (opts.signal?.aborted) break
      // resume where the .part stopped, if the server allows ranges
      const have = await fs.stat(`${dest}.part`).then((s) => s.size).catch(() => 0)
      if (attempt < attempts && have > 0) {
        await new Promise((r) => setTimeout(r, 500 * attempt))
        try {
          await downloadFileOnce(url, dest, { ...opts, resumeFrom: have })
          return
        } catch (err2) {
          lastErr = err2
          if (opts.signal?.aborted) break
          // resume not supported: restart from nothing next round
          await fs.unlink(`${dest}.part`).catch(() => {})
        }
      }
    }
  }
  throw new ProvisionError(`download failed after ${attempts} attempt(s) for ${url}: ${(lastErr as Error)?.message ?? lastErr}`)
}

async function downloadFileOnce(
  url: string,
  dest: string,
  opts: { signal?: AbortSignal; timeoutMs?: number; resumeFrom?: number } = {},
): Promise<void> {
  await fs.mkdir(path.dirname(dest), { recursive: true })
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15 * 60_000)
  const onParentAbort = () => controller.abort()
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort()
    else opts.signal.addEventListener('abort', onParentAbort, { once: true })
  }
  try {
    const headers: Record<string, string> = { 'User-Agent': 'omni-decompiler-pro' }
    if (opts.resumeFrom) headers.Range = `bytes=${opts.resumeFrom}-`
    const res = await fetch(url, { signal: controller.signal, redirect: 'follow', headers })
    if (!res.ok || !res.body) throw new ProvisionError(`download failed: HTTP ${res.status} for ${url}`)
    if (opts.resumeFrom && res.status !== 206) throw new ProvisionError('server does not support range resume')
    const tmp = `${dest}.part`
    await pipeline(Readable.fromWeb(res.body as never), createWriteStream(tmp, { flags: opts.resumeFrom ? 'a' : 'w' }))
    await fs.rename(tmp, dest)
  } finally {
    clearTimeout(timeout)
    opts.signal?.removeEventListener('abort', onParentAbort)
  }
}

export interface ReleaseAsset {
  name: string
  url: string
  size: number
  tag: string
}

/** Find an asset of the latest GitHub release, preferring earlier patterns. */
export async function latestReleaseAsset(
  owner: string,
  repo: string,
  patterns: RegExp[],
  opts: { signal?: AbortSignal } = {},
): Promise<ReleaseAsset> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'omni-decompiler-pro',
  }
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`
  let release: { tag_name?: string; assets?: { name: string; browser_download_url: string; size: number }[] } | undefined
  try {
    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/releases/latest`, { headers, signal: opts.signal })
    if (res.ok) release = await res.json() as typeof release
    else if (res.status === 404) {
      const listRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/releases`, { headers, signal: opts.signal })
      if (listRes.ok) release = (await listRes.json() as typeof release[])?.[0]
    } else {
      throw new ProvisionError(`GitHub API HTTP ${res.status} for ${owner}/${repo}`)
    }
  } catch (err) {
    if (err instanceof ProvisionError) throw err
    throw new ProvisionError(`GitHub API unreachable for ${owner}/${repo}: ${(err as Error).message}`)
  }
  const assets = release?.assets ?? []
  for (const pattern of patterns) {
    const asset = assets.find((a) => pattern.test(a.name))
    if (asset) {
      return { name: asset.name, url: asset.browser_download_url, size: asset.size, tag: release?.tag_name ?? 'latest' }
    }
  }
  throw new ProvisionError(`no matching release asset in ${owner}/${repo}@${release?.tag_name ?? 'latest'} (patterns: ${patterns.map((p) => p.source).join(', ')})`)
}

/**
 * Minimal ZIP extractor: parses the central directory, supports stored and
 * deflated entries, refuses zip64/encrypted archives, and rejects entries
 * escaping the destination directory.
 */
export async function unzip(zipPath: string, destDir: string): Promise<string[]> {
  const out: string[] = []
  const fd = await fs.open(zipPath, 'r')
  try {
    const size = (await fd.stat()).size
    if (size < 22) throw new ProvisionError('invalid zip: too small')
    const tailLen = Math.min(size, 64 * 1024 + 22)
    const tail = Buffer.alloc(tailLen)
    await fd.read(tail, 0, tailLen, size - tailLen)
    let eocd = -1
    for (let i = tailLen - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
    }
    if (eocd < 0) throw new ProvisionError('invalid zip: end-of-central-directory not found')
    if (tail.readUInt32LE(eocd + 16) === 0xFFFFFFFF) throw new ProvisionError('zip64 archives are not supported')
    const cdSize = tail.readUInt32LE(eocd + 12)
    const cdOffset = tail.readUInt32LE(eocd + 16)
    const cd = Buffer.alloc(cdSize)
    await fd.read(cd, 0, cdSize, cdOffset)
    await fs.mkdir(destDir, { recursive: true })
    let p = 0
    while (p + 46 <= cdSize) {
      if (cd.readUInt32LE(p) !== 0x02014b50) break
      const method = cd.readUInt16LE(p + 10)
      const flags = cd.readUInt16LE(p + 8)
      const compSize = cd.readUInt32LE(p + 20)
      const uncompSize = cd.readUInt32LE(p + 24)
      const nameLen = cd.readUInt16LE(p + 28)
      const extraLen = cd.readUInt16LE(p + 30)
      const commentLen = cd.readUInt16LE(p + 32)
      const localOffset = cd.readUInt32LE(p + 42)
      const name = cd.subarray(p + 46, p + 46 + nameLen).toString('utf8')
      p += 46 + nameLen + extraLen + commentLen
      if (flags & 0x1) throw new ProvisionError(`encrypted zip entry not supported: ${name}`)
      if (compSize === 0xFFFFFFFF || uncompSize === 0xFFFFFFFF || localOffset === 0xFFFFFFFF) {
        throw new ProvisionError('zip64 archives are not supported')
      }
      const target = path.join(destDir, name)
      if (path.relative(destDir, path.resolve(target)).startsWith('..')) {
        throw new ProvisionError(`zip entry escapes destination: ${name}`)
      }
      if (name.endsWith('/')) {
        await fs.mkdir(target, { recursive: true })
        continue
      }
      const lh = Buffer.alloc(30)
      await fd.read(lh, 0, 30, localOffset)
      if (lh.readUInt32LE(0) !== 0x04034b50) throw new ProvisionError(`invalid local header for ${name}`)
      const dataStart = localOffset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28)
      const comp = Buffer.alloc(compSize)
      await fd.read(comp, 0, compSize, dataStart)
      let raw: Buffer
      if (method === 0) raw = comp
      else if (method === 8) raw = zlib.inflateRawSync(comp)
      else throw new ProvisionError(`unsupported zip compression(${method}) for ${name}`)
      if (raw.length !== uncompSize) throw new ProvisionError(`size mismatch for ${name}`)
      await fs.mkdir(path.dirname(target), { recursive: true })
      await fs.writeFile(target, raw)
      out.push(target)
    }
    return out
  } finally {
    await fd.close()
  }
}

/** List the entry names of a ZIP via its central directory (no extraction). */
export async function listZipEntries(zipPath: string): Promise<string[]> {
  const names: string[] = []
  const fd = await fs.open(zipPath, 'r')
  try {
    const size = (await fd.stat()).size
    if (size < 22) return names
    const tailLen = Math.min(size, 64 * 1024 + 22)
    const tail = Buffer.alloc(tailLen)
    await fd.read(tail, 0, tailLen, size - tailLen)
    let eocd = -1
    for (let i = tailLen - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
    }
    if (eocd < 0) return names
    if (tail.readUInt32LE(eocd + 16) === 0xFFFFFFFF) return names
    const cd = Buffer.alloc(tail.readUInt32LE(eocd + 12))
    await fd.read(cd, 0, cd.length, tail.readUInt32LE(eocd + 16))
    let p = 0
    while (p + 46 <= cd.length) {
      if (cd.readUInt32LE(p) !== 0x02014b50) break
      const nameLen = cd.readUInt16LE(p + 28)
      names.push(cd.subarray(p + 46, p + 46 + nameLen).toString('utf8'))
      p += 46 + nameLen + cd.readUInt16LE(p + 30) + cd.readUInt16LE(p + 32)
    }
    return names
  } finally {
    await fd.close()
  }
}

/** Minimal .tar.gz extractor (ustar + GNU longname). */
export async function untarGz(tarPath: string, destDir: string): Promise<string[]> {
  const out: string[] = []
  const buf = zlib.gunzipSync(await fs.readFile(tarPath))
  await fs.mkdir(destDir, { recursive: true })
  let p = 0
  let pendingName: string | null = null
  while (p + 512 <= buf.length) {
    const h = buf.subarray(p, p + 512)
    if (h.every((b) => b === 0)) break
    const name = h.subarray(0, 100).toString('utf8').replace(/\0+$/, '')
    const type = String.fromCharCode(h[156] ?? 0)
    const size = parseInt(h.subarray(124, 136).toString('ascii').replace(/\0+$/, '').trim(), 8) || 0
    const isUstar = h.subarray(257, 262).toString() === 'ustar'
    let full = name
    if (isUstar) {
      const prefix = h.subarray(345, 500).toString('utf8').replace(/\0+$/, '')
      if (prefix) full = `${prefix}/${name}`
    }
    p += 512
    const blocks = Math.ceil(size / 512) * 512
    const body = buf.subarray(p, p + size)
    if (type === 'L') {
      pendingName = body.toString('utf8').replace(/\0+$/, '')
    } else {
      const targetName = pendingName ?? full
      pendingName = null
      if (type === '0' || type === '\0' || type === '7') {
        const target = path.join(destDir, targetName)
        if (!path.relative(destDir, path.resolve(target)).startsWith('..')) {
          await fs.mkdir(path.dirname(target), { recursive: true })
          await fs.writeFile(target, body)
          out.push(target)
        }
      } else if (type === '5') {
        await fs.mkdir(path.join(destDir, targetName), { recursive: true })
      }
    }
    p += blocks
  }
  return out
}

/** Recursively find the first file named `basename` under `root`. */
async function findFile(root: string, basename: string): Promise<string | null> {
  const stack = [root]
  while (stack.length) {
    const dir = stack.pop() as string
    let entries: import('node:fs').Dirent[]
    try {
      entries = await fs.readdir(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const e of entries) {
      const full = path.join(dir, e.name)
      if (e.isDirectory()) stack.push(full)
      else if (e.name === basename && !e.isSymbolicLink()) return full
    }
  }
  return null
}

/** Locate or auto-install a portable Temurin JRE (jadx needs Java 11+). */
export async function ensureJava(env: ToolEnv): Promise<string> {
  const found = resolveExe('java')
  if (found) return found
  if (!env.autoDownload) {
    throw new ProvisionError('java not found on PATH; install a JRE 11+ or enable autoDownload')
  }
  const platform = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'mac' : 'linux'
  const arch = process.arch === 'arm64' ? 'aarch64' : 'x64'
  const dir = path.join(env.cacheDir, 'jre')
  const marker = path.join(dir, '.ready')
  if (await fs.stat(marker).then(() => true).catch(() => false)) {
    const bin = await findFile(dir, process.platform === 'win32' ? 'java.exe' : 'java')
    if (bin) return bin
  }
  const url = `https://api.adoptium.net/v3/binary/latest/17/ga/${platform}/${arch}/jre/hotspot/normal/eclipse?project=jdk`
  const archive = path.join(env.cacheDir, 'downloads', `temurin-17-${platform}-${arch}.${platform === 'windows' ? 'zip' : 'tar.gz'}`)
  await downloadFile(url, archive, env)
  const extracted = platform === 'windows'
    ? await unzip(archive, dir)
    : await untarGz(archive, dir)
  void extracted
  const bin = await findFile(dir, process.platform === 'win32' ? 'java.exe' : 'java')
  if (!bin) throw new ProvisionError('Temurin JRE downloaded but java binary not found')
  await fs.writeFile(marker, String(Date.now()))
  return bin
}

/** Locate or auto-install jadx (from skylot/jadx GitHub releases) plus a JRE. */
export async function ensureJadx(env: ToolEnv): Promise<{ jadx: string; java: string }> {
  const dir = path.join(env.cacheDir, 'jadx')
  const bin = path.join(dir, 'bin', process.platform === 'win32' ? 'jadx.bat' : 'jadx')
  if (!isExecutable(bin)) {
    if (!env.autoDownload) {
      throw new ProvisionError('jadx not found; install jadx (https://github.com/skylot/jadx) or enable autoDownload')
    }
    const asset = await latestReleaseAsset('skylot', 'jadx', [/^jadx-\d+\.\d+\.\d+\.zip$/, /^jadx-gui-\d+\.\d+\.\d+-with-jre-win\.zip$/, /^jadx-gui-\d+\.\d+\.\d+\.zip$/], env)
    const archive = path.join(env.cacheDir, 'downloads', asset.name)
    await downloadFile(asset.url, archive, env)
    await unzip(archive, dir)
    if (!isExecutable(bin)) throw new ProvisionError(`jadx archive ${asset.name} did not yield bin/jadx`)
  }
  return { jadx: bin, java: await ensureJava(env) }
}

/** Environment adjustments so batch launchers use the provisioned JRE. */
export function javaEnv(javaBin: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env }
  const javaDir = path.dirname(javaBin)
  if (env.PATH && !env.PATH.split(path.delimiter).includes(javaDir)) {
    env.PATH = `${javaDir}${path.delimiter}${env.PATH}`
  } else if (!env.PATH) {
    env.PATH = javaDir
  }
  env.JAVA_HOME = path.dirname(javaDir)
  return env
}

/**
 * Locate ilspycmd: PATH, then `dotnet tool install -g ilspycmd`, then any
 * ilspycmd binary inside an ILSpy GitHub release archive. May return null when
 * only the fallback disassembler path is possible.
 */
export async function ensureIlspycmd(env: ToolEnv): Promise<string | null> {
  const found = resolveExe('ilspycmd')
  if (found) return found
  if (!env.autoDownload) return null
  // 1. dotnet global tool (works wherever a .NET SDK is installed)
  const dotnet = resolveExe('dotnet')
  if (dotnet) {
    const toolsDir = path.join(osHome(), '.dotnet', 'tools')
    const local = path.join(toolsDir, process.platform === 'win32' ? 'ilspycmd.exe' : 'ilspycmd')
    if (!isExecutable(local)) {
      const r = await run(dotnet, ['tool', 'install', '-g', 'ilspycmd'], { timeoutMs: env.timeoutMs, signal: env.signal })
      void r
    }
    if (isExecutable(local)) return local
  }
  // 2. scan ILSpy release archives for a bundled CLI build
  try {
    const platform = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos-arm64' : 'linux-x64'
    const asset = await latestReleaseAsset('icsharpcode', 'ILSpy', [new RegExp(`ILSpy_(?:selfcontained_)?${platform.replace('-', '_')}_.*\\.zip$`, 'i'), /^ILSpy_.*\.zip$/i], env)
    const dir = path.join(env.cacheDir, 'ilspy')
    const archive = path.join(env.cacheDir, 'downloads', asset.name)
    if (!await fs.stat(dir).then(() => true).catch(() => false)) {
      await downloadFile(asset.url, archive, env)
      await unzip(archive, dir)
    }
    const exe = await findFile(dir, process.platform === 'win32' ? 'ilspycmd.exe' : 'ilspycmd')
    if (exe) return exe
  } catch (err) {
    if (err instanceof ProvisionError) return null
    return null
  }
  return null
}

function osHome(): string {
  const home = process.env.USERPROFILE || process.env.HOME
  if (!home) throw new ProvisionError('cannot determine user home directory')
  return home
}

/** Locate wasm2wat natively, or provision the cross-platform `wabt` npm module. */
export async function ensureWabt(env: ToolEnv): Promise<{ kind: 'native'; bin: string } | { kind: 'npm'; moduleDir: string }> {
  const native = resolveExe('wasm2wat')
  if (native) return { kind: 'native', bin: native }
  if (!env.autoDownload) {
    throw new ProvisionError('wasm2wat not found and autoDownload is disabled')
  }
  const dir = path.join(env.cacheDir, 'npm')
  const moduleDir = path.join(dir, 'node_modules', 'wabt')
  if (!await fs.stat(moduleDir).then(() => true).catch(() => false)) {
    const npm = resolveExe('npm')
    if (!npm) throw new ProvisionError('npm is required to install the wabt package')
    await fs.mkdir(dir, { recursive: true })
    const r = await run(npm, ['install', '--prefix', dir, '--no-audit', '--no-fund', '--omit=dev', 'wabt'], { timeoutMs: env.timeoutMs, signal: env.signal })
    if (r.exitCode !== 0) throw new ProvisionError(`npm install wabt failed: ${r.stderr.slice(0, 2000)}`)
  }
  return { kind: 'npm', moduleDir }
}

/** Load the provisioned wabt module (CommonJS factory) from an ESM plugin. */
export async function loadWabt(moduleDir: string): Promise<{ readWasm: (bin: Uint8Array, features: Record<string, boolean>) => { toText: (opts?: Record<string, boolean>) => string } }> {
  const require = createRequire(pathToFileURL(path.join(path.dirname(moduleDir), 'package.json')).href)
  const factory = require(moduleDir) as () => Promise<never> | never
  return await Promise.resolve(factory()) as never
}
