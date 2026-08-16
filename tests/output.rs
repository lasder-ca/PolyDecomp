use polydecomp::{
    FileKind, NativeOutputFormat, default_output, default_output_with_format,
};
use std::path::Path;

#[test]
fn jar_output_is_directory_name() {
    let output = default_output(Path::new("sample.jar"), FileKind::JvmJar);
    assert_eq!(output, Path::new("sample-decompiled"));
}

#[test]
fn python_output_has_source_extension() {
    let output = default_output(Path::new("module.pyc"), FileKind::PythonBytecode);
    assert_eq!(output, Path::new("module.decompiled.py"));
}

#[test]
fn dotnet_output_is_csharp_file() {
    let output = default_output(Path::new("sample.dll"), FileKind::DotNet);
    assert_eq!(output, Path::new("sample.decompiled.cs"));
}

#[test]
fn wasm_output_is_wat() {
    let output = default_output(Path::new("sample.wasm"), FileKind::Wasm);
    assert_eq!(output, Path::new("sample.decompiled.wat"));
}

#[test]
fn native_output_extension_tracks_format() {
    assert_eq!(
        default_output_with_format(
            Path::new("program.exe"),
            FileKind::Native,
            NativeOutputFormat::Rust,
        ),
        Path::new("program.decompiled.rs")
    );
    assert_eq!(
        default_output_with_format(
            Path::new("program.exe"),
            FileKind::Native,
            NativeOutputFormat::Json,
        ),
        Path::new("program.decompiled.json")
    );
}
