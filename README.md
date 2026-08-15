# PolyDecomp

PolyDecomp is a **self-contained Rust decompiler/disassembler** with a native GUI and CLI. Version 0.3 removes the external decompiler-backend model: the release binary does not require Ghidra, CFR, JADX, pycdc, LuaDec, WABT, ILSpy, RetDec, or `objdump`.

日本語 / English UI is included in the same executable.

## Built-in formats

| Input | Built-in implementation | Output |
|---|---|---|
| JVM `.class` | class-file parser, constant pool, descriptors, JVM instruction decoder | Java-like source + bytecode comments |
| JVM `.jar` | internal ZIP reader + JVM engine | source tree |
| Android `.dex` | DEX strings/types/protos/classes/methods/code-item parser | Java-like source tree |
| Android `.apk` | internal ZIP reader + all `classes*.dex` files | source tree |
| CPython `.pyc` | pyc header, marshal/code-object reader, wordcode reconstruction | Python-like source/report |
| Lua `.luac` | Lua 5.1 prototype/instruction decoder; structural recovery for 5.2–5.4 | Lua-like source/report |
| WebAssembly `.wasm` | internally linked Rust WebAssembly printer | WAT |
| .NET `.exe/.dll` | PE/CLR metadata and IL structural analysis | C#-like source/report |
| PE / ELF / Mach-O | internal object parser, x86/x64 decoder, AArch64 basic semantic decoder | C-like pseudocode/disassembly |
| Go / Rust binaries | native engine + language markers | C-like pseudocode/disassembly |
| unknown binary | internal strings + hex structural analysis | analysis report |

“Decompiler” does not mean that compiler-lost information can be recreated. Optimized native binaries can lose variable names, comments, source types, control-flow structure, generics and other source-level information. PolyDecomp reconstructs what is recoverable and annotates lower-confidence output instead of inventing missing source.

## GUI

Run without arguments:

```bash
polydecomp
```

Features:

- drag and drop
- automatic format/language detection
- Japanese / English switch
- output preview
- background decompilation so the UI stays responsive
- no decompiler executable installation screen because the engines are built in

## CLI

```bash
polydecomp detect program.exe
polydecomp doctor
polydecomp decompile Example.class
polydecomp decompile app.apk -o app-decompiled
polydecomp decompile program.exe -o program.decompiled.c --force
```

`doctor` reports the built-in capabilities rather than searching the machine for external programs.

## Build

```bash
cargo build --release
```

Quality checks used by CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release
```

## Safety limits

Untrusted binaries are **parsed, not executed**. Archive traversal is rejected and archive/member/input size limits are enforced to reduce accidental resource exhaustion. PolyDecomp does not launch the file being analyzed.

The GUI may invoke the operating system file manager only when the user clicks **Open output**; this is unrelated to decompilation.

## Release builds

GitHub Actions builds release binaries for:

- Windows x86_64
- Linux x86_64
- macOS ARM64

A successful `main` CI run for a new package version triggers the release workflow, which creates a GitHub Release and uploads the three platform binaries.

## License

MIT
