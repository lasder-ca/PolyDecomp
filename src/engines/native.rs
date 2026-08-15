use super::{hexdump, printable_strings};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, SectionIndex, SectionKind, SymbolKind,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone)]
struct Function {
    name: String,
    address: u64,
    size: u64,
    section: SectionIndex,
}

fn architecture_name(arch: Architecture) -> &'static str {
    match arch {
        Architecture::I386 => "x86",
        Architecture::X86_64 => "x86_64",
        Architecture::Arm => "arm",
        Architecture::Aarch64 => "aarch64",
        Architecture::Riscv32 => "riscv32",
        Architecture::Riscv64 => "riscv64",
        _ => "other",
    }
}

fn x86_disassembly(bytes: &[u8], address: u64, bitness: u32, indent: &str) -> String {
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut formatted = String::new();
    let mut out = String::new();
    let mut count = 0usize;
    while decoder.can_decode() && count < 1_000_000 {
        let instruction = decoder.decode();
        formatted.clear();
        formatter.format(&instruction, &mut formatted);
        let ip = instruction.ip();
        let _ = writeln!(out, "{indent}// 0x{ip:016x}: {formatted}");
        count += 1;
    }
    if decoder.can_decode() {
        let _ = writeln!(out, "{indent}// ... instruction limit reached ...");
    }
    out
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

fn aarch64_instruction(word: u32, pc: u64) -> String {
    if word == 0xd65f_03c0 {
        return "return; // ret".to_owned();
    }
    if word & 0xfc00_0000 == 0x1400_0000 {
        let imm = sign_extend(word & 0x03ff_ffff, 26) << 2;
        let target = pc.wrapping_add_signed(imm);
        return format!("goto L_{target:x}; // b");
    }
    if word & 0xfc00_0000 == 0x9400_0000 {
        let imm = sign_extend(word & 0x03ff_ffff, 26) << 2;
        let target = pc.wrapping_add_signed(imm);
        return format!("sub_{target:x}(); // bl");
    }
    if word & 0xff00_0010 == 0x5400_0000 {
        let imm19 = (word >> 5) & 0x7ffff;
        let target = pc.wrapping_add_signed(sign_extend(imm19, 19) << 2);
        let cond = word & 0xf;
        return format!("if (cond_{cond:x}) goto L_{target:x}; // b.cond");
    }
    if word & 0x7f00_0000 == 0x1100_0000 {
        let rd = word & 0x1f;
        let rn = (word >> 5) & 0x1f;
        let imm = (word >> 10) & 0xfff;
        let shift = if word & (1 << 22) != 0 { 12 } else { 0 };
        let value = imm << shift;
        let is_sub = word & (1 << 30) != 0;
        let op = if is_sub { "-" } else { "+" };
        return format!("x{rd} = x{rn} {op} 0x{value:x};");
    }
    if word & 0x7f80_0000 == 0x5280_0000 || word & 0x7f80_0000 == 0x7280_0000 {
        let rd = word & 0x1f;
        let imm16 = (word >> 5) & 0xffff;
        let hw = (word >> 21) & 0x3;
        return format!("x{rd} = 0x{:x}; // mov wide", u64::from(imm16) << (hw * 16));
    }
    if word == 0xd503_201f {
        return "/* nop */".to_owned();
    }
    format!("/* .word 0x{word:08x} */")
}

fn aarch64_disassembly(bytes: &[u8], address: u64, indent: &str) -> String {
    let mut out = String::new();
    for (index, chunk) in bytes.chunks_exact(4).take(1_000_000).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let pc = address.saturating_add((index * 4) as u64);
        let pseudo = aarch64_instruction(word, pc);
        let _ = writeln!(out, "{indent}{pseudo:<48} // 0x{pc:016x}  {word:08x}");
    }
    out
}

fn render_function(file: &object::File<'_>, function: &Function, arch: Architecture) -> String {
    let mut out = String::new();
    let Ok(section) = file.section_by_index(function.section) else {
        return out;
    };
    let Ok(section_data) = section.data() else {
        return out;
    };
    let section_address = section.address();
    let Some(delta) = function.address.checked_sub(section_address) else {
        return out;
    };
    let Ok(start) = usize::try_from(delta) else {
        return out;
    };
    if start >= section_data.len() {
        return out;
    }
    let requested = usize::try_from(function.size).unwrap_or(0);
    let size = if requested == 0 {
        section_data.len().saturating_sub(start).min(64 * 1024)
    } else {
        requested
    };
    let end = start.saturating_add(size).min(section_data.len());
    let bytes = &section_data[start..end];
    let safe_name = function
        .name
        .replace(|c: char| !(c.is_ascii_alphanumeric() || c == '_'), "_");
    let _ = writeln!(
        out,
        "void {safe_name}(void) {{ // 0x{:x}, {} bytes",
        function.address,
        bytes.len()
    );
    match arch {
        Architecture::X86_64 => out.push_str(&x86_disassembly(bytes, function.address, 64, "    ")),
        Architecture::I386 => out.push_str(&x86_disassembly(bytes, function.address, 32, "    ")),
        Architecture::Aarch64 => {
            out.push_str(&aarch64_disassembly(bytes, function.address, "    "))
        }
        _ => {
            out.push_str(
                "    // Built-in semantic decoder for this architecture is not complete.\n",
            );
            for line in hexdump(bytes, function.address, 128 * 1024).lines() {
                let _ = writeln!(out, "    // {line}");
            }
        }
    }
    out.push_str("}\n\n");
    out
}

fn collect_functions(file: &object::File<'_>) -> Vec<Function> {
    let mut functions = Vec::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.kind() != SymbolKind::Text || symbol.address() == 0 {
            continue;
        }
        let Some(section) = symbol.section_index() else {
            continue;
        };
        let name = symbol
            .name()
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or("sub")
            .to_owned();
        functions.push(Function {
            name,
            address: symbol.address(),
            size: symbol.size(),
            section,
        });
    }
    functions.sort_by_key(|f| (f.section.0, f.address));
    functions.dedup_by(|a, b| a.address == b.address && a.section == b.section);
    if !functions.is_empty() {
        return functions;
    }

    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let size = section.size();
        if size == 0 {
            continue;
        }
        let name = section
            .name()
            .unwrap_or("text")
            .replace(|c: char| !(c.is_ascii_alphanumeric() || c == '_'), "_");
        functions.push(Function {
            name: format!("section_{name}"),
            address: section.address(),
            size,
            section: section.index(),
        });
    }
    functions
}

pub fn decompile_native(data: &[u8]) -> Result<String, String> {
    let file = object::File::parse(data).map_err(|error| format!("object parse error: {error}"))?;
    let arch = file.architecture();
    let mut out = String::new();
    let _ = writeln!(out, "/* PolyDecomp built-in native decompiler");
    let _ = writeln!(out, " * format: {:?}", file.format());
    let _ = writeln!(
        out,
        " * architecture: {} ({arch:?})",
        architecture_name(arch)
    );
    let _ = writeln!(out, " * entry: 0x{:x}", file.entry());
    let _ = writeln!(out, " */\n");

    let mut sections = BTreeMap::new();
    for section in file.sections() {
        let name = section.name().unwrap_or("?").to_owned();
        sections.insert(section.address(), (name, section.size(), section.kind()));
    }
    out.push_str("/* sections\n");
    for (address, (name, size, kind)) in sections {
        let _ = writeln!(out, " * 0x{address:016x}  {size:8}  {kind:?}  {name}");
    }
    out.push_str(" */\n\n");

    let strings = printable_strings(data, 6, 2_000);
    if !strings.is_empty() {
        out.push_str("/* recovered strings (first 2000)\n");
        for value in strings {
            let _ = writeln!(out, " * {:?}", value);
        }
        out.push_str(" */\n\n");
    }

    let functions = collect_functions(&file);
    if functions.is_empty() {
        out.push_str("/* No executable text section was found. */\n");
    } else {
        for function in functions.iter().take(50_000) {
            out.push_str(&render_function(&file, function, arch));
        }
        if functions.len() > 50_000 {
            out.push_str("/* function output truncated at safety limit */\n");
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_ret() {
        assert!(aarch64_instruction(0xd65f03c0, 0x1000).contains("return"));
    }

    #[test]
    fn arm64_branch() {
        assert!(aarch64_instruction(0x14000001, 0x1000).contains("goto"));
    }
}
