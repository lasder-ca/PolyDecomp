# PolyDecomp

PolyDecomp is a **Rust-native, cross-platform decompiler frontend** with both a CLI and a Japanese/English GUI. It detects the input format and routes it to the best installed decompiler backend.

> PolyDecomp is a frontend/orchestrator. It does not claim to reconstruct the exact original source when compilation has removed names, comments, types, generics, macros, or control-flow structure.

## Features

- Native Rust application: one executable contains the GUI and CLI.
- Japanese / English GUI with runtime Japanese system-font discovery.
- Drag & drop, automatic file detection, backend selection, background execution, backend health view, and output preview.
- Safe process invocation without shell interpolation.
- Backend timeout and output-overwrite protection in the CLI.
- Windows, Linux and macOS GitHub Actions builds.

## Supported inputs

| Input | Preferred backend | Fallback |
|---|---|---|
| JVM `.class` / `.jar` | CFR / FernFlower | `javap` for one `.class` |
| Android `.apk` / `.dex` | JADX | — |
| Python `.pyc` | pycdc | pycdas |
| Lua `.luac` | LuaDec | — |
| WebAssembly `.wasm` | WABT `wasm-decompile` | `wasm2wat` |
| .NET managed `.exe` / `.dll` | ILSpy `ilspycmd` | — |
| Native PE / ELF / Mach-O | Ghidra headless | RetDec, then `objdump` |
| Go / Rust / Swift native programs | Ghidra headless | RetDec, then `objdump` |
| Existing source | copied as-is | — |

Go, Rust, Swift, C and C++ native binaries are decompiled to **C-like pseudocode** by native decompilers; the original source language is only heuristically identified when useful markers remain.

## GUI

Run without arguments:

```bash
polydecomp
```

or explicitly:

```bash
polydecomp gui
```

The GUI supports Japanese and English from the language selector in the upper-right corner.

## CLI

Detect a file:

```bash
polydecomp detect program.exe
```

Show available engines:

```bash
polydecomp doctor
```

Automatically decompile:

```bash
polydecomp decompile Example.class -o Example.java
polydecomp decompile app.apk -o app-decompiled
polydecomp decompile module.pyc -o module.py
polydecomp decompile module.wasm -o module.c
polydecomp decompile app.exe -o app.c
```

Select a backend:

```bash
polydecomp decompile app.exe -o app.c --backend ghidra
polydecomp decompile Example.class -o Example.java --backend cfr
```

## Backend discovery

PolyDecomp looks in `PATH` for executable backends and additionally supports:

- `GHIDRA_HOME=/path/to/ghidra`
- `CFR_JAR=/path/to/cfr.jar`
- `FERNFLOWER_JAR=/path/to/fernflower.jar`

CFR can also be placed at `~/.local/share/polydecomp/cfr.jar` or `~/.polydecomp/cfr.jar`.

## Build from source

PolyDecomp uses Rust 1.92+ because egui/eframe 0.35 requires it.

```bash
cargo build --release
cargo test --all-targets
```

On Ubuntu/Debian, install the native GUI build dependencies first:

```bash
sudo apt-get update
sudo apt-get install -y \
  libclang-dev libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libxkbcommon-dev libwayland-dev libx11-dev pkg-config libssl-dev
```

## CI

`.github/workflows/ci.yml` runs formatting, Clippy, tests and release builds. It also produces downloadable native build artifacts for:

- Windows x64
- Linux x64
- macOS ARM64

Dependabot checks Cargo and GitHub Actions dependencies weekly.

## Legal / intended use

Use PolyDecomp only on software you own or have permission to inspect. A decompiler is useful for interoperability, debugging, recovery, auditing and authorized reverse engineering, but local law and software licenses can impose additional restrictions.
