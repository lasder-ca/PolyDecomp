use crate::model::Capability;

pub fn capabilities() -> Vec<Capability> {
    [
        ("JVM class/JAR", "builtin-jvm", "high", "Parses class files, constant pools, descriptors and JVM bytecode without Java/CFR."),
        ("Android DEX/APK", "builtin-dex", "medium", "Parses DEX strings, types, classes, methods and code items directly; APK extraction is internal."),
        ("CPython .pyc", "builtin-pyc", "medium", "Parses pyc headers and marshal/code-object structure when supported, with safe structural fallback."),
        ("Lua bytecode", "builtin-lua", "medium", "Version-aware header analysis, string recovery and Lua 5.1 instruction decoding with safe fallback."),
        ("WebAssembly", "builtin-wasm", "high", "Prints valid WAT internally using a linked Rust library; no wabt executable."),
        (".NET PE assembly", "builtin-dotnet", "medium", "Reads CLR metadata streams and emits a C#-oriented metadata/IL report without ILSpy."),
        ("PE / ELF / Mach-O", "builtin-native", "medium", "Parses object files internally, disassembles x86/x64, decodes common AArch64 instructions, and emits C-like pseudocode."),
        ("Go / Rust native", "builtin-native", "medium", "Uses native object analysis plus Go/Rust markers; no Ghidra/RetDec dependency."),
        ("Source files", "builtin-source", "exact", "Copies source text after detection; no decompilation is needed."),
    ]
    .into_iter()
    .map(|(format, engine, fidelity, notes)| Capability {
        format: format.to_owned(),
        engine: engine.to_owned(),
        fidelity: fidelity.to_owned(),
        notes: notes.to_owned(),
    })
    .collect()
}
