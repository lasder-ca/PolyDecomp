use polydecomp::{DecompileOptions, decompile};
use std::fs;

fn assert_native_parse_rejected(file_name: &str, bytes: &[u8]) {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join(file_name);
    let output = dir.path().join("output.txt");
    fs::write(&input, bytes).expect("write malformed fixture");

    let error = decompile(&input, &output, &DecompileOptions::default())
        .expect_err("malformed native object must be rejected");

    assert!(
        error.to_string().starts_with("object parse error:"),
        "unexpected error: {error}"
    );
    assert!(
        !output.exists(),
        "failed native parsing must not leave a partial output file"
    );
}

#[test]
fn rejects_truncated_elf_header() {
    assert_native_parse_rejected("truncated.elf", b"\x7fELF");
}

#[test]
fn rejects_truncated_pe_header() {
    assert_native_parse_rejected("truncated.exe", b"MZ");
}

#[test]
fn rejects_invalid_pe_header_offset() {
    let mut bytes = vec![0_u8; 64];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_native_parse_rejected("invalid-offset.exe", &bytes);
}

#[test]
fn rejects_truncated_macho_header() {
    assert_native_parse_rejected("truncated.macho", &[0xcf, 0xfa, 0xed, 0xfe]);
}
