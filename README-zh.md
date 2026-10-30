# Omni-Decompiler-Pro 万物反编译引擎

> 面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）的通用反编译引擎：**把文件扔给它，它把反编译后的代码吐给你。**

给 `omni_decompile` 工具一个文件路径——Android APK、DEX、Windows PE（含 .NET）、Linux ELF、WebAssembly 模块或普通压缩包——引擎会嗅探魔数、挑选当前可用的最优开源反编译器，执行后把反编译出的源码（或反汇编）合并成一份清单返回。

缺失的反编译器在首次使用时**自动下载**（可在插件配置中关闭）：便携版 `jadx` + Adoptium Temurin JRE、经 dotnet 工具源或 ILSpy 发布包供给的 `ilspycmd`、以及 `wabt` npm 包。

## 安装

```bash
dsh plugin add doujiaozh/omni-decompiler-pro
```

或从本地目录安装：

```bash
dsh plugin add D:\Code\omni-decompiler-pro
```

随后让模型反编译任意文件，或直接调用工具：

```text
> 用 omni_decompile 反编译 D:\samples\app.apk
```

## 支持格式

| 格式 | 嗅探依据 | 引擎 | 产物 |
|---|---|---|---|
| Android APK / DEX / JAR / CLASS | `PK..` + manifest/dex 条目；`dex\n` | **jadx** | Java（含 Kotlin 时一并产出） |
| .NET PE（.exe/.dll） | `MZ` + CLI 头（数据目录 #14） | **ilspycmd** | C# |
| 原生 PE、ELF、Mach-O | `MZ`；`7fELF`；`feedface/fac f` | **objdump**（binutils） | 节区、动态符号、完整反汇编 |
| WebAssembly | `\0asm` | **wasm2wat** / **wabt** | WAT 文本格式 |
| ZIP / 仅资源的 APK / JAR | `PK\x03\x04` | 解压 + **递归** | 成员逐一再反编译 |
| TAR / TAR.GZ / 7z / GZ | `ustar` @257；`7z\xbc\xaf\x27\x1c`；`1f8b` | tar/7z + **递归** | 成员逐一再反编译 |
| 其它任意二进制 | 可打印字符串扫描 | **strings** 兜底 | 可打印字符串 |

当某格式的主引擎不可用（且关闭了自动下载）时，引擎优雅降级：.NET PE 回退到 `objdump` 反汇编，未知二进制回退到 `strings`——始终返回*有用内容*并附警告说明降级原因。

## 配置

在 DSH 插件设置（插件配置表单）中可改：

| 字段 | 默认值 | 含义 |
|---|---|---|
| `autoDownload` | `true` | 首次使用时自动下载缺失的开源反编译器 |
| `cacheDir` | `<临时目录>/omni-decompiler-pro` | 供给工具链的存放目录 |
| `commandTimeoutMs` | `600000`（10 分钟） | 单条外部命令超时 |
| `maxOutputChars` | `200000` | 返回清单的字符上限 |
| `keepWorkspace` | `false` | 保留中间反编译目录 |

工具还支持逐次调用覆盖参数：`path`（必填）、`maxOutputChars`、`listFiles`（保留反编译产物并返回全部文件路径）。

### 工具链先决条件

常规路径无需任何预装，但以下工具能让结果更丰富：

- **objdump**（binutils / mingw-w64）——原生二进制，通常已预装。
- **Java 11+** 与 **jadx**——Android/Java，否则自动供给。
- **.NET SDK** + `dotnet tool install -g ilspycmd`——.NET 二进制；先查 PATH，再自动装 dotnet 全局工具，最后扫描 ILSpy 发布包。
- **wabt**——WebAssembly；无原生 `wasm2wat` 时使用跨平台 npm 构建。

## 工作原理

```
文件 ──► 魔数嗅探（头部 4096 字节）
      │   ├─ ZIP？枚举中央目录区分 APK / 压缩包 / JAR
      │   ├─ PE？解析 PE 头 + 数据目录 #14 判定 .NET CLI
      │   └─ ELF / Mach-O / DEX / WASM / TAR / 7z / GZ 魔数
      ▼
   格式 → 引擎路由（jadx | ilspycmd | objdump | wasm2wat | 压缩包递归）
      ▼
   child_process.spawn → 采集反编译产出的源码
      ▼
   合并清单（按 maxOutputChars 截断）+ 警告 → 工具结果
```

- `src/engine.ts`——分类、路由、各格式执行阶段与兜底。
- `src/toolchain.ts`——进程运行器（超时、中止、Windows `.bat` 引号处理）、PATH 解析、带断点续传与重试的 HTTP 下载、零依赖 ZIP 与 TAR.GZ 解压器、按工具自动供给。
- `src/index.ts`——DSH 插件入口，注册 `omni_decompile` 工具。

## 设计要点

- **不内嵌任何二进制**。只使用开源工具，按需从官方发布源（GitHub Releases、Adoptium API、npm registry）下载。
- **运行时零 npm 依赖**。插件仅靠 Node 内置能力运行；`wabt` npm 包仅在缺失原生 `wasm2wat` 时装入插件缓存。
- **可取消**。工具中止信号会传播到子进程（Windows 上整树终止），下载同样受此信号约束。
- **对沙箱友好**。解压拒绝逃逸目标目录的 zip 条目与 tar 路径；zip64 与加密压缩包直接拒绝，不作部分解压。

## 开发

```bash
pnpm install
pnpm typecheck   # tsc --noEmit
pnpm build       # tsdown → lib/
```

## 许可

MIT © doujiaozh
