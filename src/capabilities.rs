use crate::model::Capability;

pub fn capabilities() -> Vec<Capability> {
    [
        ("JVM class/JAR", "builtin-jvm", "high", "Parses class files, constant pools, descriptors and JVM bytecode without Java/CFR."),
        ("Android DEX/APK", "builtin-dex", "medium", "Parses DEX strings, types, classes, methods and code items directly; APK extraction is internal."),
        ("CPython .pyc", "builtin-pyc", "medium", "Parses pyc headers and marshal/code-object structure when supported, with safe structural fallback."),
        ("Lua bytecode", "builtin-lua", "medium", "Version-aware header analysis, string recovery and Lua 5.1 instruction decoding with safe fallback."),
        ("WebAssembly", "builtin-wasm", "high", "Prints valid WAT internally using a linked Rust library; no wabt executable."),
        (".NET PE assembly", "builtin-dotnet", "medium", "Reads CLR metadata streams and emits a C#-oriented metadata/IL report without ILSpy."),
        ("PE / ELF / Mach-O", "builtin-native-cfg", "medium", "Recovers native functions from symbols, PE x64 .pdata, the entry point, and direct-call traversal; builds per-function CFGs and emits C/Rust/Python-like pseudocode, assembly, or JSON."),
        ("Go / Rust native", "builtin-native-cfg", "medium", "Uses native object analysis plus Go/Rust markers, function recovery and CFG-based rendering; no Ghidra/RetDec dependency."),
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
