# Changelog

## 0.3.0 - 2026-08-15

- Replaced the external-backend frontend with self-contained Rust engines.
- Added built-in JVM class/JAR parsing and JVM bytecode reconstruction.
- Added built-in DEX/APK parsing and Dalvik code-item output.
- Added built-in CPython `.pyc` marshal/code-object analysis.
- Added built-in Lua bytecode analysis, including Lua 5.1 instruction decoding.
- Added built-in WebAssembly to WAT output.
- Added built-in .NET CLR metadata and IL analysis.
- Added built-in PE/ELF/Mach-O parsing, x86/x64 disassembly, and common AArch64 pseudocode.
- Kept the bilingual Japanese/English native GUI and CLI in one executable.
- Added automatic GitHub Release publishing after successful CI.
