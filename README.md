# PolyDecomp

PolyDecomp is a **self-contained Rust decompiler/disassembler** with a native GUI and CLI. The release binary does not require Ghidra, CFR, JADX, pycdc, LuaDec, WABT, ILSpy, RetDec, or `objdump`.

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
| PE / ELF / Mach-O | object parser + function recovery + CFG + native readability pass | C-like / Rust-like / Python-like / ASM / JSON |
| Go / Rust binaries | native engine + language markers + CFG/readability recovery | C-like / Rust-like / Python-like / ASM / JSON |
| unknown binary | internal strings + hex structural analysis | analysis report |

“Decompiler” does not mean that compiler-lost information can be recreated. Optimized native binaries can lose variable names, comments, source types, generics, and source-level control structures. PolyDecomp reconstructs what is recoverable instead of inventing missing source.

## Native analysis in 0.5

Native decompilation uses two internal stages. The v0.4 raw backend recovers functions and CFGs; v0.5 adds a bounded readability/lifting pass over that IR.

PolyDecomp now:

- recovers symbol-defined functions
- parses Windows x64 `.pdata` runtime-function entries
- starts analysis from the executable entry point
- recursively discovers direct-call targets when metadata is sparse
- builds basic blocks and per-function control-flow graphs
- follows conditional/unconditional branches instead of linearly sweeping all code
- symbolically propagates common x86/x64 register values across CFG edges
- applies Windows x64 or System V x86_64 ABI knowledge to infer generic arguments such as `arg0`
- names common stack slots such as `local_20`, `stack_30`, and `stack_arg_10`
- combines `cmp` / `test` with following conditional branches to produce expressions such as `arg0 == 0`
- detects loop headers from CFG back-edges
- suppresses common prologue/epilogue/no-op noise in readable source-like views
- removes unconditional jumps that only target the next natural block
- parses PE import tables and resolves common RIP-relative IAT calls to `DLL!Function` names
- resolves some RIP-relative references to recovered strings and object symbols
- retains raw assembly, addresses, confidence labels, CFG successors, and original pseudocode in enriched JSON
- emits C-like, Rust-like, Python-like, assembly, or structured JSON output

The C/Rust/Python formats are intended for reading and analysis. They are not guaranteed to compile as reconstructed source. ABI-derived arguments, inferred return expressions, and call arguments are heuristics and are labeled accordingly.

## GUI

Run without arguments:

```bash
polydecomp
```

Features:

- drag and drop
- automatic format/language detection
- Japanese / English switch
- native output selector: C / Rust / Python / ASM / JSON
- output preview
- background decompilation so the UI stays responsive
- no external decompiler installation

## CLI

```bash
polydecomp detect program.exe
polydecomp doctor

polydecomp decompile Example.class
polydecomp decompile app.apk -o app-decompiled

polydecomp decompile program.exe --format c
polydecomp decompile program.exe --format rust
polydecomp decompile program.exe --format python
polydecomp decompile program.exe --format asm
polydecomp decompile program.exe --format json
```

The native format also determines the automatic output extension (`.c`, `.rs`, `.py`, `.asm`, or `.json`).

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
