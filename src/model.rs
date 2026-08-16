use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileKind {
    JvmClass,
    JvmJar,
    AndroidDex,
    AndroidApk,
    PythonBytecode,
    LuaBytecode,
    Wasm,
    DotNet,
    Native,
    Source,
    Unknown,
}

impl FileKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JvmClass => "jvm-class",
            Self::JvmJar => "jvm-jar",
            Self::AndroidDex => "android-dex",
            Self::AndroidApk => "android-apk",
            Self::PythonBytecode => "python-bytecode",
            Self::LuaBytecode => "lua-bytecode",
            Self::Wasm => "wasm",
            Self::DotNet => "dotnet",
            Self::Native => "native",
            Self::Source => "source",
            Self::Unknown => "unknown",
        }
    }

    pub const fn output_is_directory(self) -> bool {
        matches!(self, Self::JvmJar | Self::AndroidDex | Self::AndroidApk)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NativeOutputFormat {
    #[default]
    C,
    Rust,
    Python,
    Assembly,
    Json,
}

impl NativeOutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Rust => "rust",
            Self::Python => "python",
            Self::Assembly => "asm",
            Self::Json => "json",
        }
    }

    pub const fn extension(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Rust => "rs",
            Self::Python => "py",
            Self::Assembly => "asm",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub kind: FileKind,
    pub language: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub format: String,
    pub engine: String,
    pub fidelity: String,
    pub notes: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DecompileOptions {
    pub force: bool,
    pub native_format: NativeOutputFormat,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecompileResult {
    pub input: PathBuf,
    pub output: PathBuf,
    pub engine: String,
    pub detection: Detection,
    pub fidelity: String,
}
