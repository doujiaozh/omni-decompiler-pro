// src/index.ts — DSH plugin entry: registers the `omni_decompile` tool.
//
// Throw any file at it; the engine sniffs the magic bytes and routes the file
// to the best available open-source decompiler, auto-provisioning missing
// tools when allowed by configuration.

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import * as os from 'node:os'
import * as path from 'node:path'
import Schema from 'schemastery'
import { decompile, EngineConfig, ProvisionError, type Json } from './engine.js'

export const name = 'omni-decompiler-pro'

/** Concrete tool result shape (structurally compatible with the schema-inferred type). */
export interface ToolResult {
  format: string
  engine: string
  ok: boolean
  summary: string
  code: string
  info: Record<string, Json>
  source: string
  files: string[]
  warnings: string[]
}

export interface Config {
  /** Download missing decompilers (jadx/JRE/ILSpy/wabt) into cacheDir. */
  autoDownload: boolean
  /** Where provisioned toolchains live. Empty = platform temp dir. */
  cacheDir: string
  /** Per external command budget (ms). */
  commandTimeoutMs: number
  /** Character cap for the returned decompiled listing. */
  maxOutputChars: number
  /** Keep intermediate work directories after the call. */
  keepWorkspace: boolean
}

export const Config: Schema<Config> = Schema.object({
  autoDownload: Schema.boolean().default(true).description('Auto-download missing decompilers (jadx + JRE, ILSpy, wabt) on first use.'),
  cacheDir: Schema.string().default('').description('Directory for downloaded toolchains. Empty = <temp>/omni-decompiler-pro. Examples: D:\\tools\\omni-cache'),
  commandTimeoutMs: Schema.number().default(600000).min(30000).max(3600000).description('Timeout per external decompiler command, in milliseconds.'),
  maxOutputChars: Schema.number().default(200000).min(2000).max(4000000).description('Character cap for the returned listing; larger outputs are truncated symmetrically.'),
  keepWorkspace: Schema.boolean().default(false).description('Keep intermediate decompiled directories after each call (otherwise they are removed).'),
})

export const inject = ['tools']

export function apply(ctx: Context, config: Config) {
  const defaults: Config = {
    autoDownload: true,
    cacheDir: '',
    commandTimeoutMs: 600000,
    maxOutputChars: 200000,
    keepWorkspace: false,
  }
  const cfg: Config = { ...defaults, ...config }

  const cacheDir = cfg.cacheDir || path.join(os.tmpdir(), 'omni-decompiler-pro')

  ctx.tools.register(defineTool({
    name: 'omni_decompile',
    description: [
      'Universal decompiler. Give it any compiled binary or package file path and it returns decompiled source code or disassembly.',
      'Supported: Android APK/DEX/JAR/CLASS (jadx → Java), .NET PE (ilspycmd → C#), native PE/ELF/Mach-O (objdump disassembly + symbols), WebAssembly WASM (wasm2wat → WAT), and archives (ZIP/7z/TAR/GZ, recursing into members).',
      'Missing open-source tools are downloaded automatically when enabled in plugin config. Long runs are normal on first use.',
    ].join(' '),

    parameters: {
      path: {
        type: 'string', required: true,
        description: 'Absolute or workspace-relative path of the file to decompile (e.g. app.apk, program.exe, lib.so, app.wasm, classes.dex).',
      },
      maxOutputChars: {
        type: 'integer',
        description: 'Optional override of the configured character cap for the returned listing.',
      },
      listFiles: {
        type: 'boolean',
        description: 'If true, keep decompiled files on disk and return every file path (disables automatic cleanup).',
      },
    },

    output: {
      schema: {
        type: 'object',
        properties: {
          format: { type: 'string', description: 'Detected format, e.g. android/apk, pe/dotnet, elf, wasm.' },
          engine: { type: 'string', description: 'The engine that produced the output, e.g. jadx, ilspycmd, objdump, wasm2wat.' },
          summary: { type: 'string', description: 'One-line human-readable result.' },
          code: { type: 'string', description: 'Decompiled listing (truncated to the character cap).' },
          files: { type: 'array', items: { type: 'string' }, description: 'Paths of every extracted source file when a multi-file decompiler ran.' },
          info: { type: 'object', additionalProperties: true, description: 'Facts about the analyzed file (path, size, magic).' },
          warnings: { type: 'array', items: { type: 'string' }, description: 'Non-fatal warnings and skipped-stage notes.' },
          source: { type: 'string', description: 'Absolute path of the analyzed file.' },
          ok: { type: 'boolean', description: 'Whether a real decompiler produced the output.' },
        },
        required: ['format', 'engine', 'summary', 'code', 'files', 'info', 'warnings', 'source', 'ok'],
        additionalProperties: false,
      },

      render: (_args, value) => {
        const warnings = value.warnings ?? []
        const files = value.files ?? []
        const w = warnings.length ? `\n\nWarnings:\n${warnings.map((m) => `- ${m}`).join('\n')}` : ''
        const f = files.length ? `\n\nExtracted files (${files.length}):\n${files.slice(0, 80).map((x) => `- ${x}`).join('\n')}${files.length > 80 ? `\n… and ${files.length - 80} more` : ''}` : ''
        const text = [
          `# ${value.summary}`,
          `Format: ${value.format} · Engine: ${value.engine} · Source: ${value.source}`,
          '',
          value.code,
          w,
          f,
        ].join('\n')
        return [{ type: 'text', text }]
      },
    },

    async execute(args, exec): Promise<ToolResult> {
      const engineConfig: EngineConfig = {
        cacheDir,
        autoDownload: cfg.autoDownload,
        commandTimeoutMs: cfg.commandTimeoutMs,
        maxOutputChars: args.maxOutputChars ?? cfg.maxOutputChars,
        keepWorkspace: args.listFiles ?? cfg.keepWorkspace,
      }

      const start = Date.now()
      try {
        const result = await decompile(args.path, engineConfig, { signal: exec.signal })
        return {
          ...result,
          info: { ...result.info, elapsedMs: Date.now() - start },
        }
      } catch (err) {
        if (err instanceof ProvisionError) {
          return {
            format: 'unknown', engine: 'none', ok: false,
            summary: `decompile failed: ${err.message}`,
            code: `Omni-Decompiler-Pro could not process this file.\n\nReason: ${err.message}\n\nTroubleshooting:\n- verify the file path and that it is a readable regular file\n- for APK/DEX: install Java 11+ and jadx, or enable autoDownload in plugin config\n- for .NET: install the .NET SDK and run: dotnet tool install -g ilspycmd\n- for native binaries: install binutils/objdump (mingw-w64 on Windows)\n- for WASM: install wabt (or let the engine npm-install it)`,
            files: [], info: { file: args.path, elapsedMs: Date.now() - start }, warnings: [], source: args.path,
          }
        }
        throw err
      }
    },
  }))
}

export * from './engine.js'
