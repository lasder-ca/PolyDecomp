use polydecomp::{DecompileOptions, decompile};
use std::fs;

fn assert_wasm_parse_rejected(file_name: &str, bytes: &[u8]) {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join(file_name);
    let output = dir.path().join("output.wat");
    fs::write(&input, bytes).expect("write malformed fixture");

    let error = decompile(&input, &output, &DecompileOptions::default())
        .expect_err("malformed WebAssembly must be rejected");

    assert!(
        error.to_string().starts_with("WASM parse error:"),
        "unexpected error: {error}"
    );
    assert!(
        !output.exists(),
        "failed WebAssembly parsing must not leave a partial output file"
    );
}

#[test]
fn rejects_truncated_wasm_header() {
    assert_wasm_parse_rejected("truncated-header.wasm", b"\0asm");
}

#[test]
fn rejects_truncated_wasm_version() {
    assert_wasm_parse_rejected("truncated-version.wasm", b"\0asm\x01\0\0");
}

#[test]
fn rejects_unterminated_wasm_section_length() {
    assert_wasm_parse_rejected("unterminated-section.wasm", b"\0asm\x01\0\0\0\x01\x01\x80");
}
