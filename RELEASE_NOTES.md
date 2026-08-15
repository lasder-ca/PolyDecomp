# PolyDecomp 0.3.0

PolyDecomp is now self-contained. External decompiler executables are no longer required.

Highlights:

- Built-in JVM, DEX/APK, CPython bytecode, Lua bytecode, WebAssembly, .NET, PE/ELF/Mach-O analysis.
- x86/x64 disassembly and common AArch64 pseudocode inside the application.
- Japanese and English native GUI.
- CLI and GUI distributed as one binary.
- Input files are parsed rather than executed.

Native and heavily optimized bytecode output is necessarily approximate when compiler-lost source information is unavailable.
