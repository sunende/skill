English | [简体中文](README.md)

# IDA NO MCP

**Say goodbye to the complex, verbose, and laggy interaction mode of IDA MCP.**  

**AI Reverse Engineering, Zero Extra Configuration.**  

Simple · Fast · Intelligent · Low Cost

## Core Philosophy

Text, Source Code, and Shell are LLM's native languages.

AI is evolving rapidly with no fixed patterns—tools should stay simple. Export IDA decompilation results as source files, drop them into any AI IDE (Cursor / Claude Code / ...), and naturally benefit from indexing, parallelism, chunking (for huge decompiled functions), and other optimizations.

## Usage

### Plugin Mode

Copy `INP.py` to the IDA plugins directory:

- **Windows**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- **Linux/macOS**: `~/.idapro/plugins/`

After restarting IDA:

- **Hotkey**: `Ctrl-Shift-E` for quick export
- **Menu**: `Edit` -> `Plugins` -> `Export for AI`

## Exported Content


| File/Directory          | Content                    | Description                                                                                 |
| ----------------------- | -------------------------- | ------------------------------------------------------------------------------------------- |
| `decompile/`            | Decompiled C code          | Each successfully decompiled function as a `.c` file, with function name, address, callers, callees |
| `disassembly/`          | Disassembly fallback code  | Falls back to disassembly when decompilation fails, one `.asm` file per function with the same metadata |
| `disassembly_fallback.txt` | Disassembly fallback list | Records fallback functions, fallback reasons, and output file paths                         |
| `decompile_failed.txt`  | Hard failure list          | Records functions where both decompilation and disassembly fallback failed                  |
| `decompile_skipped.txt` | Skipped functions list     | Records skipped library functions and invalid functions                                     |
| `strings.txt`           | String table               | Includes address, length, type (ASCII/UTF-16/UTF-32), content                               |
| `imports.txt`           | Import table               | Format: `address:function_name`                                                             |
| `exports.txt`           | Export table               | Format: `address:function_name`                                                             |
| `memory/`               | Memory hexdump             | 1MB chunks, hexdump format with address, hex bytes, ASCII                                   |

## Features

### Decompiled Function Export

Each function is exported as a separate `.c` file when decompilation succeeds. If decompilation fails, the function is exported to `disassembly/` as a `.asm` file instead. Both outputs keep the same metadata header:

```c
/*
 * func-name: sub_401000
 * func-address: 0x401000
 * export-type: decompile
 * callers: 0x402000, 0x403000
 * callees: 0x404000, 0x405000
 */

// Decompiled code...
```

**Smart Handling**:

- Automatically skips library functions and invalid functions
- Automatically falls back to disassembly export when decompilation fails
- Handles special characters and duplicate function names (adds address suffix)
- Generates detailed fallback, failure, and skip logs
- Shows export progress (every 100 functions)

### Call Relationship Analysis

- **Callers**: Which functions call the current function
- **Callees**: Which functions are called by the current function
- Helps AI understand function dependencies and call chains

### Memory Export

- Exports all memory data by segments
- Maximum 1MB per file, automatically chunked
- Hexdump format with address, hex bytes, and ASCII display
- Filename format: `start_address--end_address.txt`

### Statistics

Displays detailed statistics after export:

- Total number of functions
- Successfully exported count
- Disassembly fallback count
- Skipped count (library/invalid functions)
- Failed count (with failure reasons)
- Memory export size and file count

## Tips

You can add more context in the IDB directory to give AI a complete picture:


| Directory | Content                                              |
| --------- | ---------------------------------------------------- |
| `apk/`    | APK decompilation directory (APKLab one-click export) |
| `docs/`   | Reverse engineering reports, notes                  |
| `codes/`  | exp, Frida scripts, decryptor, etc.                 |

State-of-the-art AI models can leverage all this information and scripts to provide you with the most powerful reverse engineering assistance.
