use crate::model::Tool;
use std::env;
use std::path::PathBuf;

fn executable_candidates(name: &str) -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        if std::path::Path::new(name).extension().is_some() {
            vec![name.to_owned()]
        } else {
            vec![
                format!("{name}.exe"),
                format!("{name}.cmd"),
                format!("{name}.bat"),
                name.to_owned(),
            ]
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![name.to_owned()]
    }
}

pub fn which(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        for candidate in executable_candidates(name) {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn env_file(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_file())
}

fn cfr_jar() -> Option<PathBuf> {
    if let Some(path) = env_file("CFR_JAR") {
        return Some(path);
    }
    let home = home_dir()?;
    [
        home.join(".local/share/polydecomp/cfr.jar"),
        home.join(".polydecomp/cfr.jar"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn ghidra_headless() -> Option<PathBuf> {
    if let Some(path) = which("analyzeHeadless") {
        return Some(path);
    }
    let home = env::var_os("GHIDRA_HOME").map(PathBuf::from)?;
    [
        home.join("support/analyzeHeadless"),
        home.join("support/analyzeHeadless.bat"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn tool(name: &str, path: Option<PathBuf>, true_decompiler: bool, notes: &str) -> Tool {
    Tool {
        name: name.to_owned(),
        path,
        true_decompiler,
        notes: notes.to_owned(),
    }
}

pub fn inventory() -> Vec<Tool> {
    vec![
        tool(
            "java",
            which("java"),
            false,
            "Runtime used by CFR/FernFlower",
        ),
        tool("cfr", cfr_jar(), true, "JVM class/JAR -> Java source"),
        tool(
            "fernflower",
            env_file("FERNFLOWER_JAR"),
            true,
            "Alternative JVM decompiler",
        ),
        tool(
            "javap",
            which("javap"),
            false,
            "JVM bytecode disassembly fallback",
        ),
        tool(
            "jadx",
            which("jadx"),
            true,
            "Android APK/DEX -> Java source",
        ),
        tool(
            "pycdc",
            which("pycdc"),
            true,
            "CPython .pyc -> Python source",
        ),
        tool(
            "pycdas",
            which("pycdas"),
            false,
            "Python bytecode disassembly fallback",
        ),
        tool(
            "luadec",
            which("luadec"),
            true,
            "Lua bytecode -> Lua source",
        ),
        tool(
            "wasm-decompile",
            which("wasm-decompile"),
            true,
            "WASM -> C-like source",
        ),
        tool("wasm2wat", which("wasm2wat"), false, "WASM text fallback"),
        tool("ilspycmd", which("ilspycmd"), true, ".NET/C# decompiler"),
        tool(
            "ghidra",
            ghidra_headless(),
            true,
            "Native PE/ELF/Mach-O -> C-like pseudocode",
        ),
        tool(
            "retdec",
            which("retdec-decompiler"),
            true,
            "Native fallback decompiler",
        ),
        tool(
            "objdump",
            which("objdump"),
            false,
            "Native assembly fallback",
        ),
    ]
}

pub fn find_tool(name: &str) -> Option<Tool> {
    inventory().into_iter().find(|tool| tool.name == name)
}
