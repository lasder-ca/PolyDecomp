use crate::model::{Detection, FileKind};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const JAVA_CLASS_MAGIC: &[u8; 4] = b"\xca\xfe\xba\xbe";
const ZIP_MAGIC: &[u8; 4] = b"PK\x03\x04";
const WASM_MAGIC: &[u8; 4] = b"\x00asm";
const LUA_MAGIC: &[u8; 4] = b"\x1bLua";
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const DEX_MAGIC: &[u8; 4] = b"dex\n";
const MAX_SCAN: u64 = 4 * 1024 * 1024;

const MACHO_MAGICS: [[u8; 4]; 6] = [
    [0xfe, 0xed, 0xfa, 0xce],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xcf, 0xfa, 0xed, 0xfe],
    [0xca, 0xfe, 0xba, 0xbe],
    [0xbe, 0xba, 0xfe, 0xca],
];

fn prefix(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut data = Vec::new();
    file.take(MAX_SCAN).read_to_end(&mut data)?;
    Ok(data)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn looks_like_java_class(data: &[u8], ext: &str) -> bool {
    if data.get(..4) != Some(JAVA_CLASS_MAGIC.as_slice()) {
        return false;
    }
    if ext == "class" {
        return true;
    }

    // 0xCAFEBABE is also the big-endian fat Mach-O magic. A Java class stores
    // minor/major u16 versions followed by a non-zero constant-pool count,
    // whereas fat Mach-O stores a u32 architecture count after the magic.
    // Requiring a plausible Java major and a non-zero constant pool avoids
    // classifying ordinary fat Mach-O headers as JVM bytecode when no suffix
    // is available.
    let Some(header) = data.get(4..10) else {
        return false;
    };
    let major = u16::from_be_bytes([header[2], header[3]]);
    let constant_pool_count = u16::from_be_bytes([header[4], header[5]]);
    major >= 45 && constant_pool_count > 0
}

fn native_language(data: &[u8]) -> (&'static str, f32) {
    if contains_bytes(data, b"\xff Go buildinf:")
        || contains_bytes(data, b"runtime.main") && contains_bytes(data, b"runtime.morestack")
    {
        return ("go", 0.95);
    }

    let rust_markers = [
        b"rust_begin_unwind".as_slice(),
        b"rust_eh_personality".as_slice(),
        b"core::panicking".as_slice(),
        b"std::panicking".as_slice(),
        b"alloc::".as_slice(),
    ];
    let rust_hits = rust_markers
        .iter()
        .filter(|marker| contains_bytes(data, marker))
        .count();
    if rust_hits >= 2 {
        return ("rust", 0.86);
    }

    if contains_bytes(data, b"swift_beginAccess")
        || contains_bytes(data, b"swift_release") && contains_bytes(data, b"swift_retain")
    {
        return ("swift", 0.78);
    }

    ("native", 0.70)
}

fn source_language(ext: &str) -> Option<&'static str> {
    match ext {
        "js" | "mjs" | "cjs" => Some("javascript"),
        "ts" | "mts" | "cts" => Some("typescript"),
        "py" => Some("python"),
        "lua" => Some("lua"),
        "java" => Some("java"),
        "kt" | "kts" => Some("kotlin"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        "c" | "h" => Some("c"),
        "cc" | "cpp" | "cxx" | "hpp" => Some("c++"),
        "cs" => Some("c#"),
        "swift" => Some("swift"),
        _ => None,
    }
}

pub fn detect(path: &Path) -> Result<Detection, String> {
    if !path.is_file() {
        return Err(format!("not a file: {}", path.display()));
    }

    let data = prefix(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let head4 = data.get(..4).unwrap_or(&[]);

    if looks_like_java_class(&data, &ext) {
        return Ok(Detection {
            kind: FileKind::JvmClass,
            language: "java/kotlin".to_owned(),
            description: "JVM class bytecode".to_owned(),
            confidence: 1.0,
        });
    }

    if ext == "jar" && head4 == ZIP_MAGIC {
        return Ok(Detection {
            kind: FileKind::JvmJar,
            language: "java/kotlin".to_owned(),
            description: "JVM JAR archive".to_owned(),
            confidence: 0.99,
        });
    }

    if ext == "apk" && head4 == ZIP_MAGIC {
        return Ok(Detection {
            kind: FileKind::AndroidApk,
            language: "java/kotlin".to_owned(),
            description: "Android APK archive".to_owned(),
            confidence: 0.99,
        });
    }

    if head4 == DEX_MAGIC || ext == "dex" {
        return Ok(Detection {
            kind: FileKind::AndroidDex,
            language: "java/kotlin".to_owned(),
            description: "Android DEX bytecode".to_owned(),
            confidence: 0.99,
        });
    }

    if head4 == WASM_MAGIC {
        return Ok(Detection {
            kind: FileKind::Wasm,
            language: "webassembly".to_owned(),
            description: "WebAssembly module".to_owned(),
            confidence: 1.0,
        });
    }

    if head4 == LUA_MAGIC || ext == "luac" {
        return Ok(Detection {
            kind: FileKind::LuaBytecode,
            language: "lua".to_owned(),
            description: "Lua bytecode".to_owned(),
            confidence: 0.99,
        });
    }

    if ext == "pyc" {
        return Ok(Detection {
            kind: FileKind::PythonBytecode,
            language: "python".to_owned(),
            description: "CPython bytecode cache".to_owned(),
            confidence: 0.96,
        });
    }

    let is_pe = data.starts_with(b"MZ");
    let is_elf = head4 == ELF_MAGIC;
    let is_macho = MACHO_MAGICS.iter().any(|magic| head4 == magic);

    if is_pe && contains_bytes(&data, b"BSJB") {
        return Ok(Detection {
            kind: FileKind::DotNet,
            language: "c#/.net".to_owned(),
            description: ".NET managed assembly".to_owned(),
            confidence: 0.92,
        });
    }

    if is_pe || is_elf || is_macho {
        let (language, confidence) = native_language(&data);
        let format = if is_pe {
            "PE"
        } else if is_elf {
            "ELF"
        } else {
            "Mach-O"
        };
        return Ok(Detection {
            kind: FileKind::Native,
            language: language.to_owned(),
            description: format!("{format} native executable/library"),
            confidence,
        });
    }

    if let Some(language) = source_language(&ext) {
        return Ok(Detection {
            kind: FileKind::Source,
            language: language.to_owned(),
            description: "Source file (no decompilation required)".to_owned(),
            confidence: 0.90,
        });
    }

    Ok(Detection {
        kind: FileKind::Unknown,
        language: "unknown".to_owned(),
        description: "Unknown or unsupported file format".to_owned(),
        confidence: 0.20,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn temp(ext: &str, bytes: &[u8]) -> NamedTempFile {
        let mut file = tempfile::Builder::new().suffix(ext).tempfile().expect("tempfile");
        file.write_all(bytes).expect("write");
        file
    }

    #[test]
    fn detects_java_class() {
        let file = temp(".class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34");
        assert_eq!(detect(file.path()).expect("detect").kind, FileKind::JvmClass);
    }

    #[test]
    fn detects_java_class_without_extension() {
        let file = temp("", b"\xca\xfe\xba\xbe\x00\x00\x00\x3d\x00\x01");
        assert_eq!(detect(file.path()).expect("detect").kind, FileKind::JvmClass);
    }

    #[test]
    fn keeps_fat_macho_with_cafebabe_magic_native() {
        let file = temp(
            "",
            b"\xca\xfe\xba\xbe\x00\x00\x00\x02\x01\x00\x00\x07\x00\x00\x00\x03",
        );
        assert_eq!(detect(file.path()).expect("detect").kind, FileKind::Native);
    }

    #[test]
    fn detects_wasm() {
        let file = temp(".wasm", b"\x00asm\x01\x00\x00\x00");
        assert_eq!(detect(file.path()).expect("detect").kind, FileKind::Wasm);
    }

    #[test]
    fn detects_lua_bytecode() {
        let file = temp(".luac", b"\x1bLua\x54\x00");
        assert_eq!(detect(file.path()).expect("detect").kind, FileKind::LuaBytecode);
    }

    #[test]
    fn detects_dex() {
        let file = temp(".dex", b"dex\n035\0");
        assert_eq!(detect(file.path()).expect("detect").kind, FileKind::AndroidDex);
    }

    #[test]
    fn detects_go_native_marker() {
        let mut bytes = b"\x7fELF".to_vec();
        bytes.extend_from_slice(b".....\xff Go buildinf:.....");
        let file = temp("", &bytes);
        let detection = detect(file.path()).expect("detect");
        assert_eq!(detection.kind, FileKind::Native);
        assert_eq!(detection.language, "go");
    }
}
