pub fn decompile_wasm(data: &[u8]) -> Result<String, String> {
    if !data.starts_with(b"\0asm") {
        return Err("not a WebAssembly module".to_owned());
    }
    wasmprinter::print_bytes(data).map_err(|error| format!("WASM parse error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prints_minimal_module() {
        let wat = decompile_wasm(b"\0asm\x01\0\0\0").expect("minimal wasm");
        assert!(wat.contains("module"));
    }
}
