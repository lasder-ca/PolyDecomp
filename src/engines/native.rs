use crate::model::NativeOutputFormat;
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use object::{
    Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, SectionIndex, SectionKind,
    SymbolKind,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;

const MAX_FUNCTIONS: usize = 50_000;
const MAX_BLOCKS_PER_FUNCTION: usize = 4_096;
const MAX_INSTRUCTIONS_PER_FUNCTION: usize = 50_000;
const MAX_DISCOVERED_FUNCTIONS: usize = 8_192;
const UNKNOWN_FUNCTION_LIMIT: usize = 256 * 1024;
const MAX_STRINGS: usize = 2_000;

#[derive(Debug, Clone)]
struct Function {
    name: String,
    address: u64,
    size: u64,
    section: SectionIndex,
    origin: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct NativeInstruction {
    address: u64,
    assembly: String,
    pseudocode: String,
    control: String,
    target: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct BasicBlock {
    address: u64,
    successors: Vec<u64>,
    instructions: Vec<NativeInstruction>,
}

#[derive(Debug, Clone, Serialize)]
struct FunctionAnalysis {
    name: String,
    address: u64,
    size: u64,
    origin: String,
    blocks: Vec<BasicBlock>,
}

#[derive(Debug, Serialize)]
struct NativeReport {
    format: String,
    architecture: String,
    entry: u64,
    sections: Vec<SectionReport>,
    recovered_strings: Vec<String>,
    functions: Vec<FunctionAnalysis>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SectionReport {
    name: String,
    address: u64,
    size: u64,
    kind: String,
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

fn safe_name(value: &str) -> String {
    let mut out = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    if out.is_empty() {
        out.push_str("sub");
    }
    if out.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        out.insert(0, '_');
    }
    out
}

fn section_for_address(file: &object::File<'_>, address: u64) -> Option<SectionIndex> {
    file.sections().find_map(|section| {
        let start = section.address();
        let end = start.checked_add(section.size())?;
        (address >= start && address < end).then(|| section.index())
    })
}

fn address_is_executable(file: &object::File<'_>, address: u64) -> bool {
    file.sections().any(|section| {
        if section.kind() != SectionKind::Text {
            return false;
        }
        let start = section.address();
        let Some(end) = start.checked_add(section.size()) else {
            return false;
        };
        address >= start && address < end
    })
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let b = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let b = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let b = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn pe_image_base(data: &[u8]) -> Option<u64> {
    if data.get(..2)? != b"MZ" {
        return None;
    }
    let pe = usize::try_from(read_u32(data, 0x3c)?).ok()?;
    if data.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let optional = pe.checked_add(24)?;
    match read_u16(data, optional)? {
        0x20b => read_u64(data, optional.checked_add(24)?),
        0x10b => read_u32(data, optional.checked_add(28)?).map(u64::from),
        _ => None,
    }
}

fn collect_pdata_functions(file: &object::File<'_>, data: &[u8]) -> Vec<Function> {
    if file.format() != BinaryFormat::Pe || file.architecture() != Architecture::X86_64 {
        return Vec::new();
    }
    let Some(image_base) = pe_image_base(data) else {
        return Vec::new();
    };
    let Some(pdata) = file.section_by_name(".pdata") else {
        return Vec::new();
    };
    let Ok(bytes) = pdata.data() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for chunk in bytes.as_chunks::<12>().0 {
        let begin = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let end = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        if begin == 0 || end <= begin {
            continue;
        }
        let address = image_base.saturating_add(u64::from(begin));
        let size = u64::from(end - begin);
        if size > 16 * 1024 * 1024 {
            continue;
        }
        let Some(section) = section_for_address(file, address) else {
            continue;
        };
        out.push(Function {
            name: format!("sub_{address:x}"),
            address,
            size,
            section,
            origin: "pe-pdata",
        });
    }
    out
}

fn insert_function(map: &mut BTreeMap<u64, Function>, function: Function) {
    match map.get(&function.address) {
        Some(existing) => {
            let existing_is_generated = existing.name.starts_with("sub_");
            let incoming_is_named = !function.name.starts_with("sub_");
            if incoming_is_named && existing_is_generated {
                map.insert(function.address, function);
            } else if existing.size == 0 && function.size != 0 {
                let mut merged = existing.clone();
                merged.size = function.size;
                if incoming_is_named {
                    merged.name = function.name;
                    merged.origin = function.origin;
                }
                map.insert(merged.address, merged);
            }
        }
        None => {
            map.insert(function.address, function);
        }
    }
}

fn collect_seed_functions(file: &object::File<'_>, data: &[u8]) -> Vec<Function> {
    let mut functions = BTreeMap::new();

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
        insert_function(
            &mut functions,
            Function {
                name,
                address: symbol.address(),
                size: symbol.size(),
                section,
                origin: "symbol",
            },
        );
    }

    for function in collect_pdata_functions(file, data) {
        insert_function(&mut functions, function);
    }

    let entry = file.entry();
    if entry != 0
        && let Some(section) = section_for_address(file, entry)
    {
        let entry_function = Function {
            name: format!("entry_{entry:x}"),
            address: entry,
            size: 0,
            section,
            origin: "entry-point",
        };
        insert_function(&mut functions, entry_function);
        if let Some(existing) = functions.get_mut(&entry)
            && existing.name.starts_with("sub_")
        {
            existing.name = format!("entry_{entry:x}");
        }
    }

    functions.into_values().collect()
}

fn function_bytes(file: &object::File<'_>, function: &Function) -> Option<Vec<u8>> {
    let section = file.section_by_index(function.section).ok()?;
    let section_data = section.data().ok()?;
    let delta = function.address.checked_sub(section.address())?;
    let start = usize::try_from(delta).ok()?;
    if start >= section_data.len() {
        return None;
    }
    let requested = usize::try_from(function.size)
        .ok()
        .filter(|size| *size != 0);
    let size = requested.unwrap_or_else(|| {
        section_data
            .len()
            .saturating_sub(start)
            .min(UNKNOWN_FUNCTION_LIMIT)
    });
    let end = start.saturating_add(size).min(section_data.len());
    Some(section_data[start..end].to_vec())
}

fn control_kind(mnemonic: &str) -> &'static str {
    if mnemonic.starts_with("ret") || mnemonic.starts_with("iret") {
        "return"
    } else if mnemonic == "jmp" {
        "jump"
    } else if mnemonic.starts_with('j')
        || mnemonic.starts_with("loop")
        || matches!(mnemonic, "jcxz" | "jecxz" | "jrcxz")
    {
        "conditional"
    } else if mnemonic == "call" {
        "call"
    } else {
        "next"
    }
}

fn split_asm(assembly: &str) -> (&str, &str) {
    assembly
        .split_once(char::is_whitespace)
        .map_or((assembly, ""), |(a, b)| (a, b.trim()))
}

fn pseudo_from_asm(assembly: &str, control: &str, target: Option<u64>) -> String {
    let (mnemonic, operands) = split_asm(assembly);
    if control == "return" {
        return "return;".to_owned();
    }
    if control == "call" {
        return target.map_or_else(
            || format!("call_indirect({operands});"),
            |address| format!("sub_{address:x}();"),
        );
    }
    if control == "jump" {
        return target.map_or_else(
            || format!("goto_indirect({operands});"),
            |address| format!("goto L_{address:x};"),
        );
    }
    if control == "conditional" {
        return target.map_or_else(
            || format!("if ({mnemonic}) goto_indirect({operands});"),
            |address| format!("if (condition_{mnemonic}) goto L_{address:x};"),
        );
    }

    let Some((left, right)) = operands.split_once(',') else {
        return match mnemonic {
            "nop" => "/* nop */".to_owned(),
            "inc" => format!("{operands} += 1;"),
            "dec" => format!("{operands} -= 1;"),
            "push" => format!("stack_push({operands});"),
            "pop" => format!("{operands} = stack_pop();"),
            _ => format!("/* {assembly} */"),
        };
    };
    let left = left.trim();
    let right = right.trim();

    match mnemonic {
        "mov" | "movzx" | "movsx" | "movsxd" => format!("{left} = {right};"),
        "lea" => format!("{left} = address_of({right});"),
        "add" => format!("{left} += {right};"),
        "sub" => format!("{left} -= {right};"),
        "and" => format!("{left} &= {right};"),
        "or" => format!("{left} |= {right};"),
        "xor" if left == right => format!("{left} = 0;"),
        "xor" => format!("{left} ^= {right};"),
        "shl" | "sal" => format!("{left} <<= {right};"),
        "shr" | "sar" => format!("{left} >>= {right};"),
        "imul" => format!("{left} *= {right};"),
        "cmp" => format!("compare({left}, {right});"),
        "test" => format!("test_bits({left}, {right});"),
        _ => format!("/* {assembly} */"),
    }
}

fn decode_x86_cfg(bytes: &[u8], address: u64, bitness: u32) -> FunctionAnalysis {
    let end = address.saturating_add(bytes.len() as u64);
    let mut pending = VecDeque::from([address]);
    let mut queued = BTreeSet::from([address]);
    let mut decoded_addresses = BTreeSet::new();
    let mut blocks = Vec::new();
    let mut instruction_total = 0usize;

    while let Some(block_start) = pending.pop_front() {
        if blocks.len() >= MAX_BLOCKS_PER_FUNCTION
            || instruction_total >= MAX_INSTRUCTIONS_PER_FUNCTION
        {
            break;
        }
        if block_start < address || block_start >= end {
            continue;
        }
        let offset = usize::try_from(block_start - address).unwrap_or(bytes.len());
        if offset >= bytes.len() {
            continue;
        }

        let mut decoder =
            Decoder::with_ip(bitness, &bytes[offset..], block_start, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        let mut formatted = String::new();
        let mut instructions = Vec::new();
        let mut successors = Vec::new();

        while decoder.can_decode() && instruction_total < MAX_INSTRUCTIONS_PER_FUNCTION {
            let instruction = decoder.decode();
            let ip = instruction.ip();
            if ip >= end || !decoded_addresses.insert(ip) {
                if ip >= address && ip < end {
                    successors.push(ip);
                }
                break;
            }
            instruction_total += 1;

            formatted.clear();
            formatter.format(&instruction, &mut formatted);
            let assembly = formatted.clone();
            let (mnemonic, _) = split_asm(&assembly);
            let control = control_kind(mnemonic);
            let raw_target = if matches!(control, "jump" | "conditional" | "call") {
                let target = instruction.near_branch_target();
                (target != 0).then_some(target)
            } else {
                None
            };
            let target = raw_target.filter(|target| *target >= address && *target < end);
            let next = instruction.next_ip();

            instructions.push(NativeInstruction {
                address: ip,
                pseudocode: pseudo_from_asm(&assembly, control, raw_target),
                assembly,
                control: control.to_owned(),
                target: raw_target,
            });

            match control {
                "return" => break,
                "jump" => {
                    if let Some(target) = target {
                        successors.push(target);
                    }
                    break;
                }
                "conditional" => {
                    if let Some(target) = target {
                        successors.push(target);
                    }
                    if next < end {
                        successors.push(next);
                    }
                    break;
                }
                _ => {
                    if next >= end {
                        break;
                    }
                }
            }
        }

        successors.sort_unstable();
        successors.dedup();
        for successor in &successors {
            if queued.insert(*successor) {
                pending.push_back(*successor);
            }
        }
        if !instructions.is_empty() {
            blocks.push(BasicBlock {
                address: block_start,
                successors,
                instructions,
            });
        }
    }

    blocks.sort_by_key(|block| block.address);
    FunctionAnalysis {
        name: String::new(),
        address,
        size: bytes.len() as u64,
        origin: String::new(),
        blocks,
    }
}

fn direct_call_targets(analysis: &FunctionAnalysis) -> Vec<u64> {
    let mut targets = BTreeSet::new();
    for block in &analysis.blocks {
        for instruction in &block.instructions {
            if instruction.control == "call"
                && let Some(target) = instruction.target
            {
                targets.insert(target);
            }
        }
    }
    targets.into_iter().collect()
}

fn discover_x86_functions(
    file: &object::File<'_>,
    functions: &mut Vec<Function>,
    arch: Architecture,
) {
    if !matches!(arch, Architecture::I386 | Architecture::X86_64) || functions.len() >= 512 {
        return;
    }

    let bitness = if arch == Architecture::I386 { 32 } else { 64 };
    let mut known = functions
        .iter()
        .map(|function| function.address)
        .collect::<BTreeSet<_>>();
    let mut queue = functions
        .iter()
        .map(|function| function.address)
        .collect::<VecDeque<_>>();
    let mut by_address = functions
        .iter()
        .cloned()
        .map(|function| (function.address, function))
        .collect::<BTreeMap<_, _>>();

    while let Some(address) = queue.pop_front() {
        if known.len() >= MAX_DISCOVERED_FUNCTIONS {
            break;
        }
        let Some(function) = by_address.get(&address).cloned() else {
            continue;
        };
        let Some(bytes) = function_bytes(file, &function) else {
            continue;
        };
        let analysis = decode_x86_cfg(&bytes, address, bitness);
        for target in direct_call_targets(&analysis) {
            if !address_is_executable(file, target) || !known.insert(target) {
                continue;
            }
            let Some(section) = section_for_address(file, target) else {
                continue;
            };
            let discovered = Function {
                name: format!("sub_{target:x}"),
                address: target,
                size: 0,
                section,
                origin: "recursive-call",
            };
            by_address.insert(target, discovered.clone());
            functions.push(discovered);
            queue.push_back(target);
        }
    }
}

fn infer_unknown_sizes(file: &object::File<'_>, functions: &mut [Function]) {
    functions.sort_by_key(|function| (function.section.0, function.address));
    for index in 0..functions.len() {
        if functions[index].size != 0 {
            continue;
        }
        let address = functions[index].address;
        let section_index = functions[index].section;
        let next = functions
            .iter()
            .skip(index + 1)
            .find(|function| function.section == section_index && function.address > address)
            .map(|function| function.address);
        let section_end = file
            .section_by_index(section_index)
            .ok()
            .and_then(|section| section.address().checked_add(section.size()));
        let end = next.or(section_end).unwrap_or(address);
        functions[index].size = end
            .saturating_sub(address)
            .min(UNKNOWN_FUNCTION_LIMIT as u64);
    }
}

fn collect_functions(file: &object::File<'_>, data: &[u8]) -> Vec<Function> {
    let arch = file.architecture();
    let mut functions = collect_seed_functions(file, data);
    discover_x86_functions(file, &mut functions, arch);
    infer_unknown_sizes(file, &mut functions);
    functions.sort_by_key(|function| (function.address != file.entry(), function.address));
    functions.dedup_by_key(|function| function.address);
    functions
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

fn aarch64_instruction(word: u32, pc: u64) -> (String, &'static str, Option<u64>) {
    if word == 0xd65f_03c0 {
        return ("return;".to_owned(), "return", None);
    }
    if word & 0xfc00_0000 == 0x1400_0000 {
        let imm = sign_extend(word & 0x03ff_ffff, 26) << 2;
        let target = pc.wrapping_add_signed(imm);
        return (format!("goto L_{target:x};"), "jump", Some(target));
    }
    if word & 0xfc00_0000 == 0x9400_0000 {
        let imm = sign_extend(word & 0x03ff_ffff, 26) << 2;
        let target = pc.wrapping_add_signed(imm);
        return (format!("sub_{target:x}();"), "call", Some(target));
    }
    if word & 0xff00_0010 == 0x5400_0000 {
        let imm19 = (word >> 5) & 0x7ffff;
        let target = pc.wrapping_add_signed(sign_extend(imm19, 19) << 2);
        let cond = word & 0xf;
        return (
            format!("if (cond_{cond:x}) goto L_{target:x};"),
            "conditional",
            Some(target),
        );
    }
    if word & 0x7f00_0000 == 0x1100_0000 {
        let rd = word & 0x1f;
        let rn = (word >> 5) & 0x1f;
        let imm = (word >> 10) & 0xfff;
        let shift = if word & (1 << 22) != 0 { 12 } else { 0 };
        let value = imm << shift;
        let is_sub = word & (1 << 30) != 0;
        let op = if is_sub { "-" } else { "+" };
        return (format!("x{rd} = x{rn} {op} 0x{value:x};"), "next", None);
    }
    if word & 0x7f80_0000 == 0x5280_0000 || word & 0x7f80_0000 == 0x7280_0000 {
        let rd = word & 0x1f;
        let imm16 = word >> 5 & 0xffff;
        let hw = word >> 21 & 0x3;
        return (
            format!("x{rd} = 0x{:x};", u64::from(imm16) << (hw * 16)),
            "next",
            None,
        );
    }
    if word == 0xd503_201f {
        return ("/* nop */".to_owned(), "next", None);
    }
    (format!("/* .word 0x{word:08x} */"), "next", None)
}

fn analyze_aarch64(bytes: &[u8], address: u64) -> FunctionAnalysis {
    let mut instructions = Vec::new();
    let mut successors = BTreeSet::new();
    for (index, chunk) in bytes
        .as_chunks::<4>()
        .0
        .iter()
        .take(MAX_INSTRUCTIONS_PER_FUNCTION)
        .enumerate()
    {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let pc = address.saturating_add((index * 4) as u64);
        let (pseudo, control, target) = aarch64_instruction(word, pc);
        if matches!(control, "jump" | "conditional")
            && let Some(target) = target
        {
            successors.insert(target);
        }
        instructions.push(NativeInstruction {
            address: pc,
            assembly: format!(".word 0x{word:08x}"),
            pseudocode: pseudo,
            control: control.to_owned(),
            target,
        });
    }
    FunctionAnalysis {
        name: String::new(),
        address,
        size: bytes.len() as u64,
        origin: String::new(),
        blocks: vec![BasicBlock {
            address,
            successors: successors.into_iter().collect(),
            instructions,
        }],
    }
}

fn analyze_function(
    file: &object::File<'_>,
    function: &Function,
    arch: Architecture,
) -> FunctionAnalysis {
    let Some(bytes) = function_bytes(file, function) else {
        return FunctionAnalysis {
            name: safe_name(&function.name),
            address: function.address,
            size: function.size,
            origin: function.origin.to_owned(),
            blocks: Vec::new(),
        };
    };
    let mut analysis = match arch {
        Architecture::X86_64 => decode_x86_cfg(&bytes, function.address, 64),
        Architecture::I386 => decode_x86_cfg(&bytes, function.address, 32),
        Architecture::Aarch64 => analyze_aarch64(&bytes, function.address),
        _ => FunctionAnalysis {
            name: String::new(),
            address: function.address,
            size: bytes.len() as u64,
            origin: String::new(),
            blocks: vec![BasicBlock {
                address: function.address,
                successors: Vec::new(),
                instructions: vec![NativeInstruction {
                    address: function.address,
                    assembly: "unsupported architecture".to_owned(),
                    pseudocode: "/* semantic decoding is not implemented for this architecture */"
                        .to_owned(),
                    control: "next".to_owned(),
                    target: None,
                }],
            }],
        },
    };
    analysis.name = safe_name(&function.name);
    analysis.origin = function.origin.to_owned();
    analysis
}

fn looks_human(text: &str) -> bool {
    let text = text.trim();
    if text.len() < 6 || text.len() > 4096 {
        return false;
    }
    let alpha = text.chars().filter(|c| c.is_alphabetic()).count();
    let control = text
        .chars()
        .filter(|c| c.is_control() && !c.is_whitespace())
        .count();
    control == 0 && alpha >= 2
}

fn ascii_strings(data: &[u8], output: &mut BTreeSet<String>) {
    let mut start = None;
    for (index, byte) in data.iter().copied().enumerate() {
        if matches!(byte, 0x20..=0x7e) || matches!(byte, b'\t' | b'\n' | b'\r') {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take()
            && index.saturating_sub(begin) >= 6
            && let Ok(text) = std::str::from_utf8(&data[begin..index])
        {
            let cleaned = text.split_whitespace().collect::<Vec<_>>().join(" ");
            if looks_human(&cleaned) {
                output.insert(cleaned);
            }
        }
    }
}

fn utf16le_strings(data: &[u8], output: &mut BTreeSet<String>) {
    let mut current = Vec::new();
    for pair in data.as_chunks::<2>().0 {
        let value = u16::from_le_bytes([pair[0], pair[1]]);
        if value == 0 {
            if current.len() >= 6
                && let Ok(text) = String::from_utf16(&current)
            {
                let cleaned = text.split_whitespace().collect::<Vec<_>>().join(" ");
                if looks_human(&cleaned) {
                    output.insert(cleaned);
                }
            }
            current.clear();
        } else if char::from_u32(u32::from(value))
            .is_some_and(|c| !c.is_control() || c.is_whitespace())
        {
            current.push(value);
        } else {
            current.clear();
        }
    }
}

fn readable_strings(file: &object::File<'_>) -> Vec<String> {
    let mut strings = BTreeSet::new();
    for section in file.sections() {
        if section.kind() == SectionKind::Text {
            continue;
        }
        let name = section.name().unwrap_or("");
        if matches!(name, ".pdata" | ".reloc" | "__unwind_info") {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        ascii_strings(data, &mut strings);
        utf16le_strings(data, &mut strings);
        if strings.len() >= MAX_STRINGS * 2 {
            break;
        }
    }
    strings.into_iter().take(MAX_STRINGS).collect()
}

fn sections(file: &object::File<'_>) -> Vec<SectionReport> {
    file.sections()
        .map(|section| SectionReport {
            name: section.name().unwrap_or("?").to_owned(),
            address: section.address(),
            size: section.size(),
            kind: format!("{:?}", section.kind()),
        })
        .collect()
}

fn render_header(
    out: &mut String,
    file: &object::File<'_>,
    strings: &[String],
    format: NativeOutputFormat,
) {
    let comment = match format {
        NativeOutputFormat::Python => "#",
        _ => "//",
    };
    let _ = writeln!(out, "{comment} PolyDecomp built-in native decompiler");
    let _ = writeln!(out, "{comment} Format: {:?}", file.format());
    let _ = writeln!(
        out,
        "{comment} Architecture: {} ({:?})",
        architecture_name(file.architecture()),
        file.architecture()
    );
    let _ = writeln!(out, "{comment} Entry point: 0x{:x}", file.entry());
    let _ = writeln!(
        out,
        "{comment} Function recovery: symbols + PE x64 .pdata + entry/call traversal"
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "{comment} Sections");
    for section in sections(file) {
        let _ = writeln!(
            out,
            "{comment}   0x{:016x}  {:8}  {:<14} {}",
            section.address, section.size, section.kind, section.name
        );
    }

    if !strings.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "{comment} Human-readable strings from non-code sections (first {})",
            strings.len()
        );
        for value in strings.iter().take(200) {
            let _ = writeln!(out, "{comment}   {:?}", value);
        }
        if strings.len() > 200 {
            let _ = writeln!(
                out,
                "{comment}   ... {} more strings omitted from header ...",
                strings.len() - 200
            );
        }
    }
    let _ = writeln!(out);
}

fn python_statement(statement: &str) -> String {
    let statement = statement.trim_end_matches(';');
    if let Some(target) = statement.strip_prefix("goto L_") {
        return format!("goto(\"L_{target}\")");
    }
    if let Some(rest) = statement.strip_prefix("if (condition_")
        && let Some((condition, target)) = rest.split_once(") goto L_")
    {
        return format!(
            "if condition(\"{condition}\"):\n            goto(\"L_{}\")",
            target.trim_end_matches(';')
        );
    }
    if statement.starts_with("/*") {
        return format!("# {}", statement.trim_matches(&['/', '*', ' '][..]));
    }
    statement.to_owned()
}

fn render_function_text(out: &mut String, function: &FunctionAnalysis, format: NativeOutputFormat) {
    match format {
        NativeOutputFormat::C => {
            let _ = writeln!(
                out,
                "void {}(void) {{ // 0x{:x}, {} bytes, {}",
                function.name, function.address, function.size, function.origin
            );
            for block in &function.blocks {
                let _ = writeln!(
                    out,
                    "L_{:x}: // successors: {:?}",
                    block.address, block.successors
                );
                for instruction in &block.instructions {
                    let _ = writeln!(
                        out,
                        "    {:<52} // 0x{:016x}  {}",
                        instruction.pseudocode, instruction.address, instruction.assembly
                    );
                }
                out.push('\n');
            }
            out.push_str("}\n\n");
        }
        NativeOutputFormat::Rust => {
            let _ = writeln!(
                out,
                "fn {}() {{ // pseudo-Rust, 0x{:x}, {} bytes, {}",
                function.name, function.address, function.size, function.origin
            );
            for block in &function.blocks {
                let _ = writeln!(
                    out,
                    "    // block L_{:x}; successors: {:?}",
                    block.address, block.successors
                );
                for instruction in &block.instructions {
                    let _ = writeln!(
                        out,
                        "    {:<52} // 0x{:016x}  {}",
                        instruction.pseudocode, instruction.address, instruction.assembly
                    );
                }
                out.push('\n');
            }
            out.push_str("}\n\n");
        }
        NativeOutputFormat::Python => {
            let _ = writeln!(
                out,
                "def {}():  # 0x{:x}, {} bytes, {}",
                function.name, function.address, function.size, function.origin
            );
            if function.blocks.is_empty() {
                out.push_str("    pass\n\n");
                return;
            }
            for block in &function.blocks {
                let _ = writeln!(
                    out,
                    "    # block L_{:x}; successors: {:?}",
                    block.address, block.successors
                );
                for instruction in &block.instructions {
                    let pseudo = python_statement(&instruction.pseudocode);
                    for (index, line) in pseudo.lines().enumerate() {
                        if index == 0 {
                            let _ = writeln!(
                                out,
                                "    {:<52} # 0x{:016x}  {}",
                                line, instruction.address, instruction.assembly
                            );
                        } else {
                            let _ = writeln!(out, "    {line}");
                        }
                    }
                }
                out.push('\n');
            }
            out.push('\n');
        }
        NativeOutputFormat::Assembly => {
            let _ = writeln!(
                out,
                "; function {} @ 0x{:x}, {} bytes, {}",
                function.name, function.address, function.size, function.origin
            );
            for block in &function.blocks {
                let _ = writeln!(out, "L_{:x}:", block.address);
                for instruction in &block.instructions {
                    let _ = writeln!(
                        out,
                        "    0x{:016x}: {}",
                        instruction.address, instruction.assembly
                    );
                }
            }
            out.push('\n');
        }
        NativeOutputFormat::Json => {}
    }
}

pub fn decompile_native(data: &[u8], output_format: NativeOutputFormat) -> Result<String, String> {
    let file = object::File::parse(data).map_err(|error| format!("object parse error: {error}"))?;
    let arch = file.architecture();
    let recovered_strings = readable_strings(&file);
    let functions = collect_functions(&file, data);
    let mut analyses = Vec::new();

    for function in functions.iter().take(MAX_FUNCTIONS) {
        analyses.push(analyze_function(&file, function, arch));
    }

    if output_format == NativeOutputFormat::Json {
        let mut notes = vec![
            "Native output is reconstructed from machine code and metadata; compiler-lost names, types, comments, and source structure cannot always be recovered.".to_owned(),
            "Control-flow graphs are recovered per function instead of linearly decoding the whole .text section.".to_owned(),
        ];
        if functions.len() > MAX_FUNCTIONS {
            notes.push(format!(
                "Function output truncated from {} to {MAX_FUNCTIONS} entries.",
                functions.len()
            ));
        }
        let report = NativeReport {
            format: format!("{:?}", file.format()),
            architecture: architecture_name(arch).to_owned(),
            entry: file.entry(),
            sections: sections(&file),
            recovered_strings,
            functions: analyses,
            notes,
        };
        return serde_json::to_string_pretty(&report).map_err(|error| error.to_string());
    }

    let mut out = String::new();
    render_header(&mut out, &file, &recovered_strings, output_format);
    for function in &analyses {
        render_function_text(&mut out, function, output_format);
    }
    if functions.len() > MAX_FUNCTIONS {
        let prefix = if output_format == NativeOutputFormat::Python {
            "#"
        } else {
            "//"
        };
        let _ = writeln!(
            out,
            "{prefix} Function output truncated at {MAX_FUNCTIONS} of {} recovered functions.",
            functions.len()
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_ret() {
        let (text, control, _) = aarch64_instruction(0xd65f03c0, 0x1000);
        assert!(text.contains("return"));
        assert_eq!(control, "return");
    }

    #[test]
    fn arm64_branch() {
        let (text, control, target) = aarch64_instruction(0x14000001, 0x1000);
        assert!(text.contains("goto"));
        assert_eq!(control, "jump");
        assert_eq!(target, Some(0x1004));
    }

    #[test]
    fn x86_cfg_splits_conditional_branch() {
        let bytes = [0x31, 0xc0, 0x74, 0x01, 0x90, 0xc3];
        let analysis = decode_x86_cfg(&bytes, 0x1000, 64);
        assert!(analysis.blocks.len() >= 2);
        assert!(
            analysis
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .any(|instruction| instruction.control == "conditional")
        );
    }

    #[test]
    fn pseudo_readability() {
        assert_eq!(pseudo_from_asm("xor eax,eax", "next", None), "eax = 0;");
        assert_eq!(pseudo_from_asm("mov rax,rbx", "next", None), "rax = rbx;");
    }
}
