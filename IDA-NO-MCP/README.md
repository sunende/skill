修复了原版卡死的问题，同时针对于macos进行了优化

[English](README_EN.md) | 简体中文

# IDA NO MCP

**告别 IDA MCP 复杂、冗长、卡顿的交互模式。**

**AI 逆向，无需额外配置。**

Simple · Fast · Intelligent · Low Cost

## 核心理念

Text、Source Code、Shell 是 LLM 原生语言。

AI 飞速发展，没有固定模式，工具应该保持简单。

把 IDA 反编译结果导出为源码文件，直接丢进任意 AI IDE（Cursor / Claude Code / ...），天然适配索引、并行、切片（反编译超大函数）等优化。

## 两个版本（各司其职，建议都装）

这是一个**双轨**项目。两种产物**不是新旧替代关系，而是互补**——根据使用场景选择：

| 版本 | 形态 | 适用场景 | 不适用 |
| ---- | ---- | -------- | ------ |
| **Python 插件**（`oldpython/INP.py`） | IDA 插件（`.py`），GUI 里 `Ctrl-Shift-E` 触发 | IDA GUI 内交互导出**中小文件**；分析时随时导出当前进度 | 100MB+ 大文件（IDA 进程内分析会卡死） |
| **Rust 独立二进制**（`src/`，产物 `inp`） | 命令行可执行文件 | **大文件 / 批量 / 脚本化**；`--skip-analysis` 绕过 IDA 自动分析卡死 | 不能作为 IDA 插件加载（IDA 只加载 `.dylib`/`.so`/`.dll`，不加载可执行文件） |

**为什么需要两个？** IDA 插件必须是共享库格式（在 IDA 进程内运行），而绕过大文件分析卡死必须在 IDA 进程外做（独立二进制 + `--skip-analysis`）。两者无法合一。两个版本共享相同的输出格式（元数据头、`decompiled.c`/`function_index.txt`、`AGENTS.md`），AI 分析时无差别。

### 安装

**Python 插件**（GUI 用）—— 复制或软链到 IDA 插件目录：

```bash
# macOS/Linux
ln -s /path/to/IDA-NO-MCP/oldpython/INP.py ~/.idapro/plugins/INP.py
# Windows: 复制到 %APPDATA%\Hex-Rays\IDA Pro\plugins\INP.py
```
重启 IDA 后 `Edit → Plugins → Export for AI`（或 `Ctrl-Shift-E`）。

**Rust 二进制**（命令行用）—— 见下方「构建」章节。


### Rust 版实测性能

**reqable App.framework（24MB，54,937 函数）：**

| 指标 | Python（优化后） | **Rust** | 提升 |
| ---- | --------------- | -------- | ---- |
| 吞吐 | 112 函数/秒 | **133–159 函数/秒** | **+19%** |
| 峰值 RSS | 1,289 MB | **1,460 MB** | 持平 |


## 使用（Rust 版）

### 构建

需要 **本机已安装对应平台的 IDA Pro 9.x**（二进制运行时依赖 IDA 自带的 `libida`/`libidalib`，这些库按平台分发、不可 redistributable）+ LLVM/Clang（bindgen）。

> ⚠️ **为什么必须每平台原生构建**：不能从 macOS 交叉编译出可运行的 Windows/Linux 版。
> 二进制通过 rpath 链接到 IDA 的商业库（`libida.dylib`/`libida.dll`/`libida.so`），这些库只随对应平台的 IDA 安装包提供。SDK 的 stub 库能链接通过但运行时会崩溃（[idalib issue #24](https://github.com/idalib-rs/idalib/issues/24)）。

> ⚠️ **IDA Pro 小版本与 `idalib` 适配要求**：`idalib` 底层硬编码了 IDA 内部类的虚函数表偏移，不同 IDA 大版本物理上不能混用（否则运行时会在 `idalib_check_license` 处报 `EXC_BAD_ACCESS` 崩溃）。请根据您本机的 IDA 版本确认或修改 `Cargo.toml`（详见 [idalib 官方版本对照](https://github.com/idalib-rs/idalib#ida-support-and-dependencies)）：
>
> | IDA Pro version | Latest compatible idalib |
> | :--- | :--- |
> | **v9.3sp1** | `0.9.0` |
> | **v9.3** | `0.8.1` |
> | **v9.2** | `0.7.2` |
> | **v9.1** | `0.6.1` |
> | **v9.0sp1** | `0.4.1` |
> | **v9.0** | `0.3.0` |

```bash
# 设置 IDADIR 指向 IDA 安装目录
export IDADIR="/path/to/IDA Professional 9.3.app/Contents/MacOS"   # macOS
# export IDADIR="/path/to/ida-pro-9.3"                              # Linux
# $env:IDADIR = "C:\path\to\IDA Professional 9.3"                   # Windows PowerShell

export LIBCLANG_PATH="/Library/Developer/CommandLineTools/usr/lib"  # macOS (bindgen 需要)
cargo build --release
# 产物：target/release/inp  (macOS/Linux) 或 target/release/inp.exe (Windows)
```

**本地开发**（用 checkout 出来的 idalib 源码而非 crates.io 版本）：参考 `Cargo.toml.dev.example`。


### 产物

| 平台 | 文件 | 类型 |
| ---- | ---- | ---- |
| macOS | `inp`（无后缀） | Mach-O 可执行文件 |
| Linux | `inp`（无后缀） | ELF 可执行文件 |
| Windows | `inp.exe` | PE 可执行文件 |

注意产物是**可执行文件**，不是 dll/dylib/so（那些是共享库后缀，不适用于本工具的独立二进制架构）。

### 运行

```bash
# macOS/Linux：需让动态链接器找到 IDA 库
export DYLD_LIBRARY_PATH="$IDADIR"   # macOS
# export LD_LIBRARY_PATH="$IDADIR"   # Linux

# 小文件（auto 模式自动选 legacy/consolidated）
./target/release/inp <binary_or_idb.i64> -o <output_dir>

# 大文件（关键：--skip-analysis 绕过 IDA 自动分析，否则 177MB 二进制会卡 14+ 分钟）
./target/release/inp huge_framework.bin -o out --mode consolidated --skip-analysis

# 强制 legacy（每函数单文件，小文件推荐）
./target/release/inp small.bin -o out --mode legacy
```

选项：
- `-o <dir>` 输出目录（默认 `<input>_export_for_ai`）
- `--mode auto|legacy|consolidated`（默认 auto，>20k 函数自动切 consolidated）
- `--skip-analysis` / `-a` 跳过 IDA 自动分析（**大文件必用**，绕过 14 分钟卡死）
- `--force` 强制重新导出

## 使用（Python 版）

### 插件模式 

将 `oldpython/INP.py` 复制到 IDA 插件目录：

- **Windows**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- **Linux/macOS**: `~/.idapro/plugins/`

重启 IDA 后：

- **快捷键**: `Ctrl-Shift-E` 快速导出
- **菜单**: `Edit` -> `Plugins` -> `Export for AI`

### 批处理模式（headless）

无需打开 IDA GUI，直接命令行批量导出：

```bash
idat -A -S"INP.py <export_dir> <skip_analysis> <export_mode>" <target.i64>
#   export_dir    : 导出目录（可选，默认为原文件名_export_for_ai）
#   skip_analysis : "1" 跳过等待 auto-analysis（已分析过时用）
#   export_mode   : auto | legacy | consolidated（可选，默认 auto）
```

示例：

```bash
# 默认（auto，小文件→legacy，大文件→consolidated）
idat -A -S"INP.py /tmp/out 0 auto" target.i64

# 强制大文件合并模式
idat -A -S"INP.py /tmp/out 0 consolidated" huge_framework.i64
```

## 导出模式

为解决大文件导出导致的**内存爆炸**（原版在 270 万函数时 RAM 用到 140G）和 **token 爆炸**（100M 二进制导出近 1G、两万多个文件，AI 根本喂不进去），新增三档导出模式：

| 模式 | 触发条件 | 行为 | 适用场景 |
| ---- | -------- | ---- | -------- |
| `auto`（默认） | 函数数 ≤ 20000 → legacy；> 20000 → consolidated | 自动选择 | 绝大多数情况 |
| `legacy` | 手动指定 | 每函数一个 `.c`/`.asm`，`function_index.txt` 含完整 callers/callees | 小文件、需要每函数粒度 |
| `consolidated` | 手动指定 / auto 在大文件触发 | 单文件 `decompiled.c`（追加写、常数内存）+ `function_list.txt` + `callgraph.txt`（采样）+ 跳过 `memory/` + 短串过滤 | 大文件（Unity framework、Go 二进制等） |

**consolidated 模式如何省内存/token：**

- 不再在内存里攒 `function_index` / `addr_to_info`（原版 Mac 140G 爆炸的根因），改为流式 append 写。
- 单文件 `decompiled.c`（追加写），而非两万多个小文件。
- 跳过昂贵的全量 caller/callee 图遍历（大文件 CPU 杀手），改由 `callgraph.txt` 从 entry/export 做 N 跳 BFS 采样提供骨架。
- 默认跳过 `memory/`（raw hex 对 AI 价值低且最占 token）。
- strings 按最小长度过滤短串。

阈值与参数在 `INP.py` 顶部可调：`LARGE_BINARY_FUNC_THRESHOLD`、`LARGE_CALLGRAPH_BFS_HOPS`、`LARGE_CALLGRAPH_MAX_NODES`、`LARGE_STRING_MIN_LEN`。

## 导出内容


| 文件/目录               | 内容           | 说明                                                                        |
| ----------------------- | -------------- | --------------------------------------------------------------------------- |
| `decompiled.c`          | 合并反编译代码 | **consolidated 模式**：所有函数合并到单文件，每函数含元数据头，追加写常数内存 |
| `decompile/`            | 反编译 C 代码  | **legacy 模式**：每个成功反编译的函数一个`.c` 文件，包含函数名、地址、调用者(callers)、被调用者(callees) |
| `disassembly/`          | 反汇编回退代码 | 反编译失败时回退到反汇编导出，每个函数一个`.asm` 文件，保留相同元数据（legacy）       |
| `function_list.txt`     | 函数列表       | **consolidated 模式**：每函数单行 `地址 \| 名 \| 类型 \| 回退原因`            |
| `function_index.txt`    | 函数索引       | **legacy 模式**：每函数含 callers/callees 地址（流式写，不在内存攒全量）       |
| `callgraph.txt`         | 采样调用图     | **consolidated 模式**：从 entry/export 出发 N 跳 BFS 的关注子图               |
| `AGENTS.md`             | AI 导航上下文  | 让 Cursor / Claude Code 等 AI 自动理解导出布局，无需每次重新学习（始终生成）   |
| `disassembly_fallback.txt` | 反汇编回退列表 | 记录使用反汇编回退的函数、失败原因和输出文件路径                                     |
| `decompile_failed.txt`  | 彻底失败列表   | 记录反编译和反汇编回退都失败的函数及原因                                            |
| `decompile_skipped.txt` | 跳过函数列表   | 记录被跳过的库函数和无效函数                                                |
| `strings.txt`           | 字符串表       | 包含地址、长度、类型(ASCII/UTF-16/UTF-32)、内容；consolidated 模式按最小长度过滤 |
| `imports.txt`           | 导入表         | 格式:`地址:函数名`                                                          |
| `exports.txt`           | 导出表         | 格式:`地址:函数名`                                                          |
| `memory/`               | 内存 hexdump   | 按 1MB 分片，hexdump 格式，包含地址、十六进制、ASCII（**consolidated 模式跳过**） |

## 功能特性

### 反编译函数导出

每个函数优先导出为独立的 `.c` 文件；如果反编译失败，则回退导出到 `disassembly/` 目录中的 `.asm` 文件。两种输出都会保留同样的元数据头：

```c
/*
 * func-name: sub_401000
 * func-address: 0x401000
 * export-type: decompile
 * callers: 0x402000, 0x403000
 * callees: 0x404000, 0x405000
 */

// 反编译代码...
```

**智能处理**：

- 自动跳过库函数和无效函数
- 反编译失败时自动回退到反汇编导出
- 处理特殊字符和重名函数（添加地址后缀）
- 生成详细的回退、失败和跳过日志
- 显示导出进度（每 100 个函数）

### 调用关系分析

- **Callers**: 哪些函数调用了当前函数
- **Callees**: 当前函数调用了哪些函数
- 帮助 AI 理解函数间的依赖关系和调用链

### 内存导出

- 按段(segment)导出所有内存数据
- 每个文件最大 1MB，自动分片
- Hexdump 格式，包含地址、十六进制字节、ASCII 显示
- 文件名格式: `起始地址--结束地址.txt`

### 统计信息

导出完成后显示详细统计：

- 总函数数量
- 成功导出数量
- 反汇编回退数量
- 跳过数量（库函数/无效函数）
- 失败数量（含失败原因）
- 内存导出大小和文件数

## Tips

在 IDB 目录下可以同时添加更多上下文，让 AI 获得完整视角：


| 目录     | 内容                                 |
| -------- | ------------------------------------ |
| `apk/`   | APK 反编译目录（APKLab 一键导出）    |
| `docs/`  | 逆向分析报告、笔记                   |
| `codes/` | exp、Frida scripts、decryptor 等脚本 |

最先进的 AI 模型能够利用所有信息与脚本，为你提供最强力的逆向工程辅助。

## 变更记录

### 内存与性能（大文件）

- **修复 Mac 内存爆炸**：移除 `function_index` / `addr_to_info` 的全量内存累积（原版在 270 万函数时 RAM 用到 140G 的根因），`function_index.txt` / `function_list.txt` 改为流式 append 写，常数内存。
- **消除 O(F·degree) 索引开销**：原版写索引时对每个 caller/callee 反向解析名字，既吃内存又吃 CPU；现在只保留地址列表。部分情况下存在bug🥹🥹🥹🥹
- **consolidated 模式**：大文件（默认 > 20000 函数）自动切到单文件 `decompiled.c` + 采样 `callgraph.txt`，跳过昂贵的全量图遍历和 raw memory 导出。
- **批处理 tick**：consolidated 模式每个 timer tick 处理多个函数（受时间预算约束），提升吞吐，同时保持 UI/Cancel 响应。

### 路径健壮性

- **修复 `FileNotFoundError: [WinError 3] 'G:\\'`**：原版在原始二进制所在盘符已卸载/网络路径失效时直接崩溃。现在对所有候选目录做可写校验，按 `input_dir → idb_dir → cwd` 优先级回退；`ensure_dir` 失败时给出清晰的中文/英文混合提示而非底层 WinError。

### AI 协作

- **新增 `AGENTS.md`**：导出完成后自动在导出目录生成 AI 导航上下文（目录布局、元数据头字段、建议分析工作流），被 Cursor / Claude Code / Codex 等识别，让 AI 自动开始分析而无需每次重新学习导出格式。

### 批处理模式

- 新增第 3/4 个 ARGV：`<skip_analysis>` 和 `<export_mode>`（`auto|legacy|consolidated`），便于 headless 批量导出时控制行为。
