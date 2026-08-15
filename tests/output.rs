use polydecomp::{default_output, FileKind};
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
