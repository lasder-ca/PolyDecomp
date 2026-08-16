use crate::detect::detect;
use crate::engines::{self, dex, dotnet, jvm, lua, native, pyc, wasm};
use crate::model::{DecompileOptions, DecompileResult, Detection, FileKind, NativeOutputFormat};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecompileError {
    #[error("{0}")]
    Message(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub fn default_output(input: &Path, kind: FileKind) -> PathBuf {
    default_output_with_format(input, kind, NativeOutputFormat::C)
}

pub fn default_output_with_format(
    input: &Path,
    kind: FileKind,
    native_format: NativeOutputFormat,
) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("output");
    match kind {
        FileKind::JvmJar | FileKind::AndroidDex | FileKind::AndroidApk => {
            input.with_file_name(format!("{stem}-decompiled"))
        }
        FileKind::JvmClass => input.with_file_name(format!("{stem}.decompiled.java")),
        FileKind::PythonBytecode => input.with_file_name(format!("{stem}.decompiled.py")),
        FileKind::LuaBytecode => input.with_file_name(format!("{stem}.decompiled.lua")),
        FileKind::Wasm => input.with_file_name(format!("{stem}.decompiled.wat")),
        FileKind::DotNet => input.with_file_name(format!("{stem}.decompiled.cs")),
        FileKind::Native => {
            input.with_file_name(format!("{stem}.decompiled.{}", native_format.extension()))
        }
        FileKind::Source => input.with_file_name(format!("{stem}.copy.txt")),
        FileKind::Unknown => input.with_file_name(format!("{stem}.analysis.txt")),
    }
}

fn remove_existing(path: &Path) -> Result<(), DecompileError> {
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn prepare_output(path: &Path, force: bool) -> Result<(), DecompileError> {
    if path.exists() {
        if !force {
            return Err(DecompileError::Message(format!(
                "output already exists: {} (use --force)",
                path.display()
            )));
        }
        remove_existing(path)?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn read_input(path: &Path) -> Result<Vec<u8>, DecompileError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > engines::MAX_INPUT_BYTES as u64 {
        return Err(DecompileError::Message(format!(
            "input exceeds {} MiB safety limit",
            engines::MAX_INPUT_BYTES / 1024 / 1024
        )));
    }
    Ok(fs::read(path)?)
}

fn safe_relative(path: &str) -> Result<PathBuf, DecompileError> {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return Err(DecompileError::Message(
            "engine returned an absolute output path".to_owned(),
        ));
    }
    let mut out = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => out.push(part),
            _ => {
                return Err(DecompileError::Message(
                    "engine returned an unsafe output path".to_owned(),
                ));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(DecompileError::Message(
            "engine returned an empty output path".to_owned(),
        ));
    }
    Ok(out)
}

fn write_tree(root: &Path, files: Vec<(String, String)>) -> Result<(), DecompileError> {
    fs::create_dir_all(root)?;
    for (relative, content) in files {
        let relative = safe_relative(&relative)?;
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
    }
    Ok(())
}

fn result(
    input: &Path,
    output: &Path,
    engine: &str,
    detection: Detection,
    fidelity: &str,
) -> DecompileResult {
    DecompileResult {
        input: input.to_path_buf(),
        output: output.to_path_buf(),
        engine: engine.to_owned(),
        detection,
        fidelity: fidelity.to_owned(),
    }
}

fn unknown_report(data: &[u8]) -> String {
    let mut out = String::from("PolyDecomp built-in binary analysis\n\nRecovered strings:\n");
    for value in engines::printable_strings(data, 5, 4_000) {
        out.push_str("  ");
        out.push_str(&value);
        out.push('\n');
    }
    out.push_str("\nHex preview:\n");
    out.push_str(&engines::hexdump(data, 0, 1024 * 1024));
    out
}

pub fn decompile(
    input: &Path,
    output: &Path,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    let detection = detect(input).map_err(DecompileError::Message)?;
    let data = read_input(input)?;
    prepare_output(output, options.force)?;

    let (engine, fidelity) = match detection.kind {
        FileKind::JvmClass => {
            let text = jvm::decompile_class(&data).map_err(DecompileError::Message)?;
            fs::write(output, text)?;
            ("builtin-jvm", "high")
        }
        FileKind::JvmJar => {
            let files = jvm::decompile_jar(&data).map_err(DecompileError::Message)?;
            write_tree(output, files)?;
            ("builtin-jvm", "high")
        }
        FileKind::AndroidDex => {
            let files = dex::decompile_dex(&data).map_err(DecompileError::Message)?;
            write_tree(output, files)?;
            ("builtin-dex", "medium")
        }
        FileKind::AndroidApk => {
            let files = dex::decompile_apk(&data).map_err(DecompileError::Message)?;
            write_tree(output, files)?;
            ("builtin-dex", "medium")
        }
        FileKind::PythonBytecode => {
            fs::write(
                output,
                pyc::decompile_pyc(&data).map_err(DecompileError::Message)?,
            )?;
            ("builtin-pyc", "medium")
        }
        FileKind::LuaBytecode => {
            fs::write(
                output,
                lua::decompile_lua(&data).map_err(DecompileError::Message)?,
            )?;
            ("builtin-lua", "medium")
        }
        FileKind::Wasm => {
            fs::write(
                output,
                wasm::decompile_wasm(&data).map_err(DecompileError::Message)?,
            )?;
            ("builtin-wasm", "high")
        }
        FileKind::DotNet => {
            fs::write(
                output,
                dotnet::decompile_dotnet(&data).map_err(DecompileError::Message)?,
            )?;
            ("builtin-dotnet", "medium")
        }
        FileKind::Native => {
            fs::write(
                output,
                native::decompile_native(&data, options.native_format)
                    .map_err(DecompileError::Message)?,
            )?;
            ("builtin-native-cfg", "medium")
        }
        FileKind::Source => {
            fs::write(output, &data)?;
            ("builtin-source", "exact")
        }
        FileKind::Unknown => {
            fs::write(output, unknown_report(&data))?;
            ("builtin-analysis", "low")
        }
    };

    Ok(result(input, output, engine, detection, fidelity))
}
