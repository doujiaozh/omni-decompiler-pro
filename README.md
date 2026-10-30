# Omni-Decompiler-Pro

> Universal decompilation engine for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH): **throw any file at it, get decompiled code back.**

Give the `omni_decompile` tool a file path — an Android APK, a DEX, a Windows PE
(including .NET), a Linux ELF, a WebAssembly module, or a plain archive — and the
engine sniffs the magic bytes, picks the best available open-source decompiler,
runs it, and returns the decompiled source (or disassembly) as one listing.

Missing decompilers are **downloaded automatically** on first use (opt-out in
plugin config): portable `jadx` + Temurin JRE from Adoptium, `ilspycmd` via the
dotnet tool feed or an ILSpy release archive, and the `wabt` npm package.

## Install

```bash
dsh plugin add doujiaozh/omni-decompiler-pro
```

Or from a local checkout:

```bash
dsh plugin add D:\Code\omni-decompiler-pro
```

Then ask the model to decompile something, or call the tool directly:

```text
> Decompile D:\samples\app.apk with omni_decompile
```

## Supported formats

| Format | Detected via | Engine | Output |
|---|---|---|---|
| Android APK / DEX / JAR / CLASS | `PK..` + manifest/dex entries; `dex\n` | **jadx** | Java (Kotlin when available) |
| .NET PE (.exe/.dll) | `MZ` + CLI header (data directory #14) | **ilspycmd** | C# |
| Native PE, ELF, Mach-O | `MZ`; `7fELF`; `feedface/fac f` | **objdump** (binutils) | Sections, dynamic symbols, full disassembly |
| WebAssembly | `\0asm` | **wasm2wat** / **wabt** | WAT text format |
| ZIP / APK-resources / JAR | `PK\x03\x04` | unzip + **recurse** | Members re-decompiled individually |
| TAR / TAR.GZ / 7z / GZ | `ustar` @257; `7z\xbc\xaf\x27\x1c`; `1f8b` | tar/7z + **recurse** | Members re-decompiled individually |
| Anything else | printable-string scan | **strings** fallback | Printable strings |

When the primary engine for a format is unavailable (and downloads are
disabled), the engine degrades gracefully: a .NET PE falls back to `objdump`
disassembly, and unknown binaries fall back to `strings` — always returning
*something* useful with a warning explaining the degradation.

## Configuration

Editable in DSH plugin settings (`Plugin Configuration Forms`):

| Field | Default | Meaning |
|---|---|---|
| `autoDownload` | `true` | Download missing open-source decompilers on first use |
| `cacheDir` | `<temp>/omni-decompiler-pro` | Where provisioned toolchains live |
| `commandTimeoutMs` | `600000` (10 min) | Timeout per external command |
| `maxOutputChars` | `200000` | Character cap on the returned listing |
| `keepWorkspace` | `false` | Keep intermediate decompiled directories |

The tool also accepts per-call overrides: `path` (required), `maxOutputChars`,
and `listFiles` (keeps decompiled files on disk and returns every path).

### Toolchain prerequisites

Nothing is required for the common path, but these make results richer:

- **objdump** (binutils / mingw-w64) — native binaries. Usually preinstalled.
- **Java 11+** and **jadx** — Android/Java. Auto-provisioned otherwise.
- **.NET SDK** + `dotnet tool install -g ilspycmd` — .NET binaries. `ilspycmd` is
  looked up on PATH, then auto-installed as a dotnet global tool, then searched
  inside an ILSpy release archive.
- **wabt** — WebAssembly. The cross-platform npm build is used when no native
  `wasm2wat` exists.

## How it works

```
file ──► magic-byte sniff (4096B head)
      │   ├─ ZIP? list central directory to distinguish APK / archive / JAR
      │   ├─ PE?  parse PE header + data directory #14 to detect .NET CLI
      │   └─ ELF / Mach-O / DEX / WASM / TAR / 7z / GZ magic
      ▼
   format → engine routing (jadx | ilspycmd | objdump | wasm2wat | archive-recurse)
      ▼
   child_process.spawn → captured stdout/stdout of decompiled sources
      ▼
   merge listing (truncated to maxOutputChars) + warnings → tool result
```

- `src/engine.ts` — classification, routing, per-format stages, fallbacks.
- `src/toolchain.ts` — process runner (timeouts, abort, Windows `.bat` quoting),
  PATH resolution, HTTP download with resume+retry, zero-dependency ZIP and
  TAR.GZ extractors, and per-tool provisioning.
- `src/index.ts` — DSH plugin entry; registers the `omni_decompile` tool.

## Design notes

- **No vendored binaries.** Only open-source tools are used, downloaded from
  their official release feeds (GitHub Releases, Adoptium API, npm registry)
  on demand.
- **Zero runtime npm dependencies.** The plugin runs on Node built-ins; the
  `wabt` npm package is installed into the plugin cache only when a native
  `wasm2wat` is missing.
- **Cancellation-safe.** Tool aborts propagate to child processes (tree-kill on
  Windows); downloads honor the same signal.
- **Sandboxing-friendly.** All extraction refuses zip entries or tar paths that
  escape the destination directory; zip64/encrypted archives are rejected
  rather than partially unpacked.

## Development

```bash
pnpm install
pnpm typecheck   # tsc --noEmit
pnpm build       # tsdown → lib/
```

## License

MIT © doujiaozh
