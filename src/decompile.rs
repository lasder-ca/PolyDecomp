use crate::detect::detect;
use crate::model::{DecompileOptions, DecompileResult, Detection, FileKind};
use crate::tools::{find_tool, which};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;

const GHIDRA_SCRIPT: &str = include_str!("ghidra/ExportDecompiledC.java");

#[derive(Debug, Error)]
pub enum DecompileError {
    #[error("{0}")]
    Message(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub const fn backend_names() -> &'static [&'static str] {
    &[
        "auto",
        "cfr",
        "fernflower",
        "javap",
        "jadx",
        "pycdc",
        "pycdas",
        "luadec",
        "wasm-decompile",
        "wasm2wat",
        "ilspycmd",
        "ghidra",
        "retdec",
        "objdump",
    ]
}

pub fn default_output(input: &Path, kind: FileKind) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("output");
    match kind {
        FileKind::JvmJar | FileKind::AndroidDex | FileKind::AndroidApk | FileKind::DotNet => {
            input.with_file_name(format!("{stem}-decompiled"))
        }
        FileKind::JvmClass => input.with_file_name(format!("{stem}.decompiled.java")),
        FileKind::PythonBytecode => input.with_file_name(format!("{stem}.decompiled.py")),
        FileKind::LuaBytecode => input.with_file_name(format!("{stem}.decompiled.lua")),
        FileKind::Wasm | FileKind::Native => input.with_file_name(format!("{stem}.decompiled.c")),
        FileKind::Source => input.with_file_name(format!("{stem}.copy.txt")),
        FileKind::Unknown => input.with_file_name(format!("{stem}.decompiled.txt")),
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

fn run_with_timeout(
    mut command: Command,
    stdout_path: Option<&Path>,
    timeout_secs: u64,
) -> Result<(), DecompileError> {
    command.stdin(Stdio::null());
    if let Some(path) = stdout_path {
        let file = fs::File::create(path)?;
        command.stdout(Stdio::from(file));
    } else {
        command.stdout(Stdio::null());
    }
    let stderr_file = NamedTempFile::new()?;
    command.stderr(Stdio::from(stderr_file.reopen()?));

    let printable = format!("{command:?}");
    let mut child = command
        .spawn()
        .map_err(|error| DecompileError::Message(format!("backend could not start: {error}")))?;
    let started = Instant::now();
    let timeout = Duration::from_secs(timeout_secs.max(1));

    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            let stderr = fs::read_to_string(stderr_file.path()).unwrap_or_default();
            return Err(DecompileError::Message(format!(
                "backend failed ({status}): {}",
                stderr.trim()
            )));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DecompileError::Message(format!(
                "backend timed out after {timeout_secs}s: {printable}"
            )));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn require(name: &str) -> Result<PathBuf, DecompileError> {
    find_tool(name)
        .and_then(|tool| tool.path)
        .ok_or_else(|| DecompileError::Message(format!("required backend/tool is not installed: {name}")))
}

fn result(
    input: &Path,
    output: &Path,
    backend: &str,
    detection: Detection,
    true_decompiler: bool,
) -> DecompileResult {
    DecompileResult {
        input: input.to_path_buf(),
        output: output.to_path_buf(),
        backend: backend.to_owned(),
        detection,
        true_decompiler,
    }
}

fn decompile_jvm(
    input: &Path,
    output: &Path,
    detection: Detection,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    let backend = options.backend.as_str();
    if matches!(backend, "auto" | "cfr") {
        if let (Some(cfr), Some(java)) = (
            find_tool("cfr").and_then(|tool| tool.path),
            which("java"),
        ) {
            if detection.kind == FileKind::JvmJar {
                fs::create_dir_all(output)?;
                let mut cmd = Command::new(java);
                cmd.args(["-jar"]).arg(cfr).arg(input).arg("--outputdir").arg(output);
                run_with_timeout(cmd, None, options.timeout_secs)?;
            } else {
                let mut cmd = Command::new(java);
                cmd.args(["-jar"]).arg(cfr).arg(input);
                run_with_timeout(cmd, Some(output), options.timeout_secs)?;
            }
            return Ok(result(input, output, "cfr", detection, true));
        }
        if backend == "cfr" {
            return Err(DecompileError::Message(
                "CFR requires java and CFR_JAR (or ~/.local/share/polydecomp/cfr.jar)".to_owned(),
            ));
        }
    }

    if matches!(backend, "auto" | "fernflower") {
        if let (Some(jar), Some(java)) = (
            find_tool("fernflower").and_then(|tool| tool.path),
            which("java"),
        ) {
            let out_dir = if detection.kind == FileKind::JvmJar {
                output.to_path_buf()
            } else {
                output
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf()
            };
            fs::create_dir_all(&out_dir)?;
            let mut cmd = Command::new(java);
            cmd.args(["-jar"]).arg(jar).arg(input).arg(&out_dir);
            run_with_timeout(cmd, None, options.timeout_secs)?;
            return Ok(result(input, output, "fernflower", detection, true));
        }
        if backend == "fernflower" {
            return Err(DecompileError::Message(
                "FernFlower requires java and FERNFLOWER_JAR".to_owned(),
            ));
        }
    }

    if backend == "auto" || backend == "javap" {
        if detection.kind == FileKind::JvmJar {
            return Err(DecompileError::Message(
                "javap fallback handles a single .class only; install CFR for JAR files".to_owned(),
            ));
        }
        let javap = require("javap")?;
        let mut cmd = Command::new(javap);
        cmd.args(["-c", "-p", "-s", "-verbose"]).arg(input);
        run_with_timeout(cmd, Some(output), options.timeout_secs)?;
        return Ok(result(input, output, "javap", detection, false));
    }

    Err(DecompileError::Message(format!(
        "backend {backend} does not support JVM input"
    )))
}

fn decompile_android(
    input: &Path,
    output: &Path,
    detection: Detection,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    if !matches!(options.backend.as_str(), "auto" | "jadx") {
        return Err(DecompileError::Message(format!(
            "backend {} does not support Android input",
            options.backend
        )));
    }
    let jadx = require("jadx")?;
    fs::create_dir_all(output)?;
    let mut cmd = Command::new(jadx);
    cmd.arg("-d").arg(output).arg(input);
    run_with_timeout(cmd, None, options.timeout_secs)?;
    Ok(result(input, output, "jadx", detection, true))
}

fn decompile_python(
    input: &Path,
    output: &Path,
    detection: Detection,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    if matches!(options.backend.as_str(), "auto" | "pycdc") {
        if let Some(pycdc) = find_tool("pycdc").and_then(|tool| tool.path) {
            let mut cmd = Command::new(pycdc);
            cmd.arg(input);
            run_with_timeout(cmd, Some(output), options.timeout_secs)?;
            return Ok(result(input, output, "pycdc", detection, true));
        }
        if options.backend == "pycdc" {
            return Err(DecompileError::Message("pycdc is not installed".to_owned()));
        }
    }
    if matches!(options.backend.as_str(), "auto" | "pycdas") {
        let pycdas = require("pycdas")?;
        let mut cmd = Command::new(pycdas);
        cmd.arg(input);
        run_with_timeout(cmd, Some(output), options.timeout_secs)?;
        return Ok(result(input, output, "pycdas", detection, false));
    }
    Err(DecompileError::Message(format!(
        "backend {} does not support Python bytecode",
        options.backend
    )))
}

fn decompile_lua(
    input: &Path,
    output: &Path,
    detection: Detection,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    if !matches!(options.backend.as_str(), "auto" | "luadec") {
        return Err(DecompileError::Message(format!(
            "backend {} does not support Lua bytecode",
            options.backend
        )));
    }
    let luadec = require("luadec")?;
    let mut cmd = Command::new(luadec);
    cmd.arg(input);
    run_with_timeout(cmd, Some(output), options.timeout_secs)?;
    Ok(result(input, output, "luadec", detection, true))
}

fn decompile_wasm(
    input: &Path,
    output: &Path,
    detection: Detection,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    if matches!(options.backend.as_str(), "auto" | "wasm-decompile") {
        if let Some(tool) = find_tool("wasm-decompile").and_then(|tool| tool.path) {
            let mut cmd = Command::new(tool);
            cmd.arg(input);
            run_with_timeout(cmd, Some(output), options.timeout_secs)?;
            return Ok(result(input, output, "wasm-decompile", detection, true));
        }
        if options.backend == "wasm-decompile" {
            return Err(DecompileError::Message("wasm-decompile is not installed".to_owned()));
        }
    }
    if matches!(options.backend.as_str(), "auto" | "wasm2wat") {
        let tool = require("wasm2wat")?;
        let mut cmd = Command::new(tool);
        cmd.arg(input);
        run_with_timeout(cmd, Some(output), options.timeout_secs)?;
        return Ok(result(input, output, "wasm2wat", detection, false));
    }
    Err(DecompileError::Message(format!(
        "backend {} does not support WASM",
        options.backend
    )))
}

fn decompile_dotnet(
    input: &Path,
    output: &Path,
    detection: Detection,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    if !matches!(options.backend.as_str(), "auto" | "ilspycmd") {
        return Err(DecompileError::Message(format!(
            "backend {} does not support .NET",
            options.backend
        )));
    }
    let ilspy = require("ilspycmd")?;
    fs::create_dir_all(output)?;
    let mut cmd = Command::new(ilspy);
    cmd.arg("-p").arg("-o").arg(output).arg(input);
    run_with_timeout(cmd, None, options.timeout_secs)?;
    Ok(result(input, output, "ilspycmd", detection, true))
}

fn decompile_ghidra(
    input: &Path,
    output: &Path,
    detection: Detection,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    let ghidra = require("ghidra")?;
    let temp = TempDir::new()?;
    let project = temp.path().join("project");
    let scripts = temp.path().join("scripts");
    fs::create_dir_all(&project)?;
    fs::create_dir_all(&scripts)?;
    fs::write(scripts.join("ExportDecompiledC.java"), GHIDRA_SCRIPT)?;

    let absolute_output = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()?.join(output)
    };
    let absolute_input = input.canonicalize()?;
    let mut cmd = Command::new(ghidra);
    cmd.arg(&project)
        .arg("PolyDecompProject")
        .arg("-import")
        .arg(absolute_input)
        .arg("-scriptPath")
        .arg(&scripts)
        .arg("-postScript")
        .arg("ExportDecompiledC.java")
        .arg(absolute_output)
        .arg("-deleteProject");
    run_with_timeout(cmd, None, options.timeout_secs)?;
    if !output.is_file() || output.metadata()?.len() == 0 {
        return Err(DecompileError::Message(
            "Ghidra finished without producing decompiled output".to_owned(),
        ));
    }
    Ok(result(input, output, "ghidra", detection, true))
}

fn decompile_native(
    input: &Path,
    output: &Path,
    detection: Detection,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    if matches!(options.backend.as_str(), "auto" | "ghidra") {
        if find_tool("ghidra").is_some_and(|tool| tool.path.is_some()) {
            return decompile_ghidra(input, output, detection, options);
        }
        if options.backend == "ghidra" {
            return Err(DecompileError::Message(
                "Ghidra analyzeHeadless not found; set GHIDRA_HOME".to_owned(),
            ));
        }
    }

    if matches!(options.backend.as_str(), "auto" | "retdec") {
        if let Some(retdec) = find_tool("retdec").and_then(|tool| tool.path) {
            let mut cmd = Command::new(retdec);
            cmd.arg(input).arg("-o").arg(output);
            run_with_timeout(cmd, None, options.timeout_secs)?;
            return Ok(result(input, output, "retdec", detection, true));
        }
        if options.backend == "retdec" {
            return Err(DecompileError::Message("RetDec is not installed".to_owned()));
        }
    }

    if matches!(options.backend.as_str(), "auto" | "objdump") {
        let objdump = require("objdump")?;
        let mut cmd = Command::new(objdump);
        cmd.args(["-d", "-C", "-S"]).arg(input);
        run_with_timeout(cmd, Some(output), options.timeout_secs)?;
        return Ok(result(input, output, "objdump", detection, false));
    }

    Err(DecompileError::Message(format!(
        "backend {} does not support native input",
        options.backend
    )))
}

pub fn decompile(
    input: &Path,
    output: &Path,
    options: &DecompileOptions,
) -> Result<DecompileResult, DecompileError> {
    if !backend_names().contains(&options.backend.as_str()) {
        return Err(DecompileError::Message(format!(
            "unknown backend: {}",
            options.backend
        )));
    }
    let detection = detect(input).map_err(DecompileError::Message)?;
    prepare_output(output, options.force)?;

    match detection.kind {
        FileKind::Source => {
            fs::copy(input, output)?;
            Ok(result(input, output, "source-copy", detection, false))
        }
        FileKind::JvmClass | FileKind::JvmJar => {
            decompile_jvm(input, output, detection, options)
        }
        FileKind::AndroidDex | FileKind::AndroidApk => {
            decompile_android(input, output, detection, options)
        }
        FileKind::PythonBytecode => decompile_python(input, output, detection, options),
        FileKind::LuaBytecode => decompile_lua(input, output, detection, options),
        FileKind::Wasm => decompile_wasm(input, output, detection, options),
        FileKind::DotNet => decompile_dotnet(input, output, detection, options),
        FileKind::Native => decompile_native(input, output, detection, options),
        FileKind::Unknown => Err(DecompileError::Message(format!(
            "unsupported/unknown input: {}",
            detection.description
        ))),
    }
}
