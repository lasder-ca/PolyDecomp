use super::{
    ArgumentInfo, EnhancedBlock, EnhancedFunction, EnhancedInstruction, EnhancedReport, RawBlock,
    RawFunction, RawInstruction, RawReport,
};
use iced_x86::{Decoder, DecoderOptions};
use object::{Architecture, Object, ObjectSection, ObjectSymbol, SectionKind};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_ADDRESSED_STRINGS: usize = 8_192;
const MAX_DATAFLOW_STEPS: usize = 200_000;
const MAX_EXPRESSION_LEN: usize = 160;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SymbolicState {
    regs: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct ReferenceInfo {
    memory_reference: Option<String>,
    call_symbol: Option<String>,
}

#[derive(Debug, Clone)]
enum ComparisonKind {
    Compare,
    Test,
}

#[derive(Debug, Clone)]
struct Comparison {
    kind: ComparisonKind,
    left: String,
    right: String,
}

#[derive(Debug, Clone, Copy)]
struct Abi {
    name: &'static str,
    args: &'static [&'static str],
    volatile: &'static [&'static str],
}

const WIN64_ARGS: &[&str] = &["rcx", "rdx", "r8", "r9"];
const WIN64_VOLATILE: &[&str] = &["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];
const SYSV64_ARGS: &[&str] = &["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const SYSV64_VOLATILE: &[&str] = &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];
const NO_REGS: &[&str] = &[];

fn abi_for(report: &RawReport) -> Abi {
    if report.architecture == "x86_64" {
        if report.format.eq_ignore_ascii_case("Pe") {
            return Abi {
                name: "Windows x64",
                args: WIN64_ARGS,
                volatile: WIN64_VOLATILE,
            };
        }
        return Abi {
            name: "System V x86_64",
            args: SYSV64_ARGS,
            volatile: SYSV64_VOLATILE,
        };
    }
    Abi {
        name: "unknown/native",
        args: NO_REGS,
        volatile: NO_REGS,
    }
}

fn split_asm(assembly: &str) -> (&str, &str) {
    assembly
        .split_once(char::is_whitespace)
        .map_or((assembly, ""), |(left, right)| (left, right.trim()))
}

fn split_operands(operands: &str) -> (&str, Option<&str>) {
    operands
        .split_once(',')
        .map_or((operands.trim(), None), |(left, right)| {
            (left.trim(), Some(right.trim()))
        })
}

fn canonical_register(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "rax" | "eax" => Some("rax"),
        "rbx" | "ebx" => Some("rbx"),
        "rcx" | "ecx" => Some("rcx"),
        "rdx" | "edx" => Some("rdx"),
        "rsi" | "esi" => Some("rsi"),
        "rdi" | "edi" => Some("rdi"),
        "rbp" | "ebp" => Some("rbp"),
        "rsp" | "esp" => Some("rsp"),
        "r8" | "r8d" => Some("r8"),
        "r9" | "r9d" => Some("r9"),
        "r10" | "r10d" => Some("r10"),
        "r11" | "r11d" => Some("r11"),
        "r12" | "r12d" => Some("r12"),
        "r13" | "r13d" => Some("r13"),
        "r14" | "r14d" => Some("r14"),
        "r15" | "r15d" => Some("r15"),
        _ => None,
    }
}

fn is_partial_register(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "ax" | "al"
            | "ah"
            | "bx"
            | "bl"
            | "bh"
            | "cx"
            | "cl"
            | "ch"
            | "dx"
            | "dl"
            | "dh"
            | "si"
            | "sil"
            | "di"
            | "dil"
            | "bp"
            | "bpl"
            | "sp"
            | "spl"
            | "r8w"
            | "r8b"
            | "r9w"
            | "r9b"
            | "r10w"
            | "r10b"
            | "r11w"
            | "r11b"
            | "r12w"
            | "r12b"
            | "r13w"
            | "r13b"
            | "r14w"
            | "r14b"
            | "r15w"
            | "r15b"
    )
}

fn trim_size_prefix(value: &str) -> &str {
    let value = value.trim();
    for prefix in [
        "byte ", "word ", "dword ", "qword ", "oword ", "xmmword ", "ymmword ", "zmmword ",
        "tword ", "ptr ",
    ] {
        if let Some(stripped) = value.strip_prefix(prefix) {
            return stripped.trim();
        }
    }
    value
}

fn displacement_token(value: &str) -> Option<u64> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = value.strip_suffix('h')
        && hex.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    value.parse::<u64>().ok()
}

fn stack_variable(operand: &str) -> Option<String> {
    let operand = trim_size_prefix(operand)
        .to_ascii_lowercase()
        .replace(' ', "");
    let start = operand.find('[')?;
    let end = operand[start..].find(']')?.checked_add(start)?;
    let inner = operand.get(start + 1..end)?;

    for (base, negative_prefix, positive_prefix) in [
        ("rbp", "local", "stack_arg"),
        ("ebp", "local", "stack_arg"),
        ("rsp", "stack", "stack"),
        ("esp", "stack", "stack"),
    ] {
        if inner == base {
            return Some(format!("{positive_prefix}_00"));
        }
        if let Some(value) = inner.strip_prefix(&format!("{base}-"))
            && let Some(offset) = displacement_token(value)
        {
            return Some(format!("{negative_prefix}_{offset:x}"));
        }
        if let Some(value) = inner.strip_prefix(&format!("{base}+"))
            && let Some(offset) = displacement_token(value)
        {
            return Some(format!("{positive_prefix}_{offset:x}"));
        }
    }
    None
}

fn bounded_expression(value: String) -> String {
    if value.len() <= MAX_EXPRESSION_LEN {
        value
    } else {
        "<complex-expression>".to_owned()
    }
}

fn initial_state(abi: Abi) -> SymbolicState {
    let mut state = SymbolicState::default();
    for (index, register) in abi.args.iter().enumerate() {
        state
            .regs
            .insert((*register).to_owned(), format!("arg{index}"));
    }
    state
}

fn resolve_operand(
    operand: &str,
    state: &SymbolicState,
    reference: Option<&str>,
    locals: &mut BTreeSet<String>,
) -> String {
    let operand = trim_size_prefix(operand);
    if operand.contains('[')
        && let Some(reference) = reference
    {
        return reference.to_owned();
    }
    if let Some(local) = stack_variable(operand) {
        locals.insert(local.clone());
        return local;
    }
    if let Some(register) = canonical_register(operand) {
        return state
            .regs
            .get(register)
            .cloned()
            .unwrap_or_else(|| register.to_owned());
    }
    operand.to_owned()
}

fn state_set(state: &mut SymbolicState, destination: &str, value: String) {
    if let Some(register) = canonical_register(destination) {
        state
            .regs
            .insert(register.to_owned(), bounded_expression(value));
    } else if is_partial_register(destination) {
        let lower = destination.to_ascii_lowercase();
        let family = match lower.as_str() {
            "ax" | "al" | "ah" => Some("rax"),
            "bx" | "bl" | "bh" => Some("rbx"),
            "cx" | "cl" | "ch" => Some("rcx"),
            "dx" | "dl" | "dh" => Some("rdx"),
            _ => None,
        };
        if let Some(family) = family {
            state.regs.remove(family);
        }
    }
}

fn state_remove_destination(state: &mut SymbolicState, destination: &str) {
    if let Some(register) = canonical_register(destination) {
        state.regs.remove(register);
    }
}

fn call_display_name(symbol: &str) -> String {
    let name = symbol.rsplit('!').next().unwrap_or(symbol);
    let mut output = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if output.is_empty() {
        output.push_str("call_target");
    }
    if output.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        output.insert(0, '_');
    }
    output
}

fn call_arguments(state: &SymbolicState, abi: Abi) -> Vec<String> {
    abi.args
        .iter()
        .filter_map(|register| state.regs.get(*register).cloned())
        .collect()
}

fn apply_state(
    instruction: &RawInstruction,
    state: &mut SymbolicState,
    abi: Abi,
    reference: &ReferenceInfo,
) {
    let (mnemonic, operands) = split_asm(&instruction.assembly);
    let mnemonic = mnemonic.to_ascii_lowercase();
    let (left, right) = split_operands(operands);
    let mut scratch = BTreeSet::new();
    let memory = reference.memory_reference.as_deref();

    match mnemonic.as_str() {
        "mov" | "movzx" | "movsx" | "movsxd" => {
            if let Some(right) = right {
                let value = resolve_operand(right, state, memory, &mut scratch);
                state_set(state, left, value);
            }
        }
        "lea" => {
            if let Some(right) = right {
                let value = resolve_operand(right, state, memory, &mut scratch);
                state_set(state, left, format!("&{value}"));
            }
        }
        "xor" if right.is_some_and(|right| left.eq_ignore_ascii_case(right)) => {
            state_set(state, left, "0".to_owned());
        }
        "add" | "sub" | "and" | "or" | "xor" | "shl" | "sal" | "shr" | "sar" | "imul" => {
            if let Some(right) = right
                && let Some(register) = canonical_register(left)
            {
                let old = state
                    .regs
                    .get(register)
                    .cloned()
                    .unwrap_or_else(|| register.to_owned());
                let rhs = resolve_operand(right, state, memory, &mut scratch);
                let operator = match mnemonic.as_str() {
                    "add" => "+",
                    "sub" => "-",
                    "and" => "&",
                    "or" => "|",
                    "xor" => "^",
                    "shl" | "sal" => "<<",
                    "shr" | "sar" => ">>",
                    "imul" => "*",
                    _ => "?",
                };
                state_set(state, left, format!("({old} {operator} {rhs})"));
            }
        }
        "inc" | "dec" => {
            if let Some(register) = canonical_register(left) {
                let old = state
                    .regs
                    .get(register)
                    .cloned()
                    .unwrap_or_else(|| register.to_owned());
                let operator = if mnemonic == "inc" { "+" } else { "-" };
                state_set(state, left, format!("({old} {operator} 1)"));
            }
        }
        "pop" => state_remove_destination(state, left),
        "call" => {
            let result_name = reference
                .call_symbol
                .as_deref()
                .map(call_display_name)
                .unwrap_or_else(|| "call".to_owned());
            for register in abi.volatile {
                state.regs.remove(*register);
            }
            state
                .regs
                .insert("rax".to_owned(), format!("{result_name}_result"));
        }
        "cmp" | "test" | "push" | "nop" => {}
        _ if mnemonic.starts_with('j') || mnemonic.starts_with("ret") => {}
        _ => {
            if !left.is_empty() {
                state_remove_destination(state, left);
            }
        }
    }
}

fn merge_state(existing: &mut SymbolicState, incoming: &SymbolicState) -> bool {
    let before = existing.clone();
    existing
        .regs
        .retain(|register, value| incoming.regs.get(register) == Some(value));
    *existing != before
}

fn compute_states(
    function: &RawFunction,
    abi: Abi,
    references: &BTreeMap<u64, ReferenceInfo>,
) -> BTreeMap<u64, SymbolicState> {
    let mut blocks = BTreeMap::new();
    for block in &function.blocks {
        blocks.insert(block.address, block);
    }
    let Some(entry) = function.blocks.first().map(|block| block.address) else {
        return BTreeMap::new();
    };

    let mut states = BTreeMap::from([(entry, initial_state(abi))]);
    let mut queue = VecDeque::from([entry]);
    let mut queued = BTreeSet::from([entry]);
    let mut steps = 0usize;

    while let Some(address) = queue.pop_front() {
        queued.remove(&address);
        steps = steps.saturating_add(1);
        if steps > MAX_DATAFLOW_STEPS {
            break;
        }
        let Some(block) = blocks.get(&address) else {
            continue;
        };
        let mut state = states.get(&address).cloned().unwrap_or_default();
        for instruction in &block.instructions {
            let reference = references
                .get(&instruction.address)
                .cloned()
                .unwrap_or_default();
            apply_state(instruction, &mut state, abi, &reference);
        }

        for successor in &block.successors {
            let changed = if let Some(existing) = states.get_mut(successor) {
                merge_state(existing, &state)
            } else {
                states.insert(*successor, state.clone());
                true
            };
            if changed && queued.insert(*successor) {
                queue.push_back(*successor);
            }
        }
    }
    states
}

fn condition_expression(mnemonic: &str, comparison: Option<&Comparison>) -> String {
    let Some(comparison) = comparison else {
        return format!("condition_{mnemonic}");
    };
    let (left, right) = (&comparison.left, &comparison.right);
    let zero_test = matches!(comparison.kind, ComparisonKind::Test) && left == right;

    match mnemonic {
        "je" | "jz" if zero_test => format!("{left} == 0"),
        "jne" | "jnz" if zero_test => format!("{left} != 0"),
        "je" | "jz" => format!("{left} == {right}"),
        "jne" | "jnz" => format!("{left} != {right}"),
        "jl" | "jnge" => format!("(signed){left} < (signed){right}"),
        "jle" | "jng" => format!("(signed){left} <= (signed){right}"),
        "jg" | "jnle" => format!("(signed){left} > (signed){right}"),
        "jge" | "jnl" => format!("(signed){left} >= (signed){right}"),
        "jb" | "jnae" | "jc" => format!("{left} < {right} /* unsigned */"),
        "jbe" | "jna" => format!("{left} <= {right} /* unsigned */"),
        "ja" | "jnbe" => format!("{left} > {right} /* unsigned */"),
        "jae" | "jnb" | "jnc" => format!("{left} >= {right} /* unsigned */"),
        "js" => "sign_flag".to_owned(),
        "jns" => "!sign_flag".to_owned(),
        "jo" => "overflow_flag".to_owned(),
        "jno" => "!overflow_flag".to_owned(),
        "jp" | "jpe" => "parity_flag".to_owned(),
        "jnp" | "jpo" => "!parity_flag".to_owned(),
        _ => format!("condition_{mnemonic}"),
    }
}

fn reference_for_instruction(
    file: &object::File<'_>,
    instruction: &RawInstruction,
    architecture: &str,
    import_slots: &BTreeMap<u64, String>,
    symbols: &BTreeMap<u64, String>,
    strings: &BTreeMap<u64, String>,
    function_names: &BTreeMap<u64, String>,
) -> ReferenceInfo {
    let mut reference = ReferenceInfo::default();
    if instruction.control == "call"
        && let Some(target) = instruction.target
        && let Some(name) = function_names.get(&target)
    {
        reference.call_symbol = Some(name.clone());
    }

    let bitness = match architecture {
        "x86_64" => 64,
        "x86" => 32,
        _ => return reference,
    };
    let Some(decoded) = decode_at(file, instruction.address, bitness) else {
        return reference;
    };
    if !decoded.is_ip_rel_memory_operand() {
        return reference;
    }
    let address = decoded.ip_rel_memory_address();

    if let Some(import) = import_slots.get(&address) {
        reference.memory_reference = Some(import.clone());
        if instruction.control == "call" {
            reference.call_symbol = Some(import.clone());
        }
    } else if let Some(value) = strings.get(&address) {
        reference.memory_reference = Some(format!("{value:?}"));
    } else if let Some(symbol) = symbols.get(&address) {
        reference.memory_reference = Some(symbol.clone());
    } else {
        reference.memory_reference = Some(format!("global_{address:x}"));
    }
    reference
}

fn decode_at(file: &object::File<'_>, address: u64, bitness: u32) -> Option<iced_x86::Instruction> {
    for section in file.sections() {
        let start = section.address();
        let end = start.checked_add(section.size())?;
        if address < start || address >= end {
            continue;
        }
        let data = section.data().ok()?;
        let offset = usize::try_from(address.checked_sub(start)?).ok()?;
        let bytes = data.get(offset..)?;
        let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
        if decoder.can_decode() {
            return Some(decoder.decode());
        }
    }
    None
}

fn collect_symbols(file: &object::File<'_>) -> BTreeMap<u64, String> {
    let mut symbols = BTreeMap::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.address() == 0 {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        symbols
            .entry(symbol.address())
            .or_insert_with(|| name.to_owned());
    }
    symbols
}

fn looks_human(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 4 || value.len() > 4096 {
        return false;
    }
    let letters = value.chars().filter(|ch| ch.is_alphabetic()).count();
    let bad_controls = value
        .chars()
        .filter(|ch| ch.is_control() && !ch.is_whitespace())
        .count();
    bad_controls == 0 && letters >= 2
}

fn addressed_ascii(data: &[u8], base: u64, output: &mut BTreeMap<u64, String>) {
    let mut start = None;
    for (index, byte) in data.iter().copied().enumerate() {
        if matches!(byte, 0x20..=0x7e) || matches!(byte, b'\t' | b'\r' | b'\n') {
            start.get_or_insert(index);
            continue;
        }
        let Some(begin) = start.take() else {
            continue;
        };
        if index.saturating_sub(begin) < 4 {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&data[begin..index]) else {
            continue;
        };
        let cleaned = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if looks_human(&cleaned) {
            output
                .entry(base.saturating_add(begin as u64))
                .or_insert(cleaned);
        }
        if output.len() >= MAX_ADDRESSED_STRINGS {
            return;
        }
    }
}

fn addressed_utf16(data: &[u8], base: u64, output: &mut BTreeMap<u64, String>) {
    let mut current = Vec::new();
    let mut start = 0usize;
    for (index, pair) in data.as_chunks::<2>().0.iter().enumerate() {
        let value = u16::from_le_bytes([pair[0], pair[1]]);
        if value == 0 {
            if current.len() >= 4
                && let Ok(text) = String::from_utf16(&current)
            {
                let cleaned = text.split_whitespace().collect::<Vec<_>>().join(" ");
                if looks_human(&cleaned) {
                    output
                        .entry(base.saturating_add((start * 2) as u64))
                        .or_insert(cleaned);
                }
            }
            current.clear();
            start = index.saturating_add(1);
        } else if char::from_u32(u32::from(value))
            .is_some_and(|ch| !ch.is_control() || ch.is_whitespace())
        {
            if current.is_empty() {
                start = index;
            }
            current.push(value);
        } else {
            current.clear();
            start = index.saturating_add(1);
        }
        if output.len() >= MAX_ADDRESSED_STRINGS {
            return;
        }
    }
}

fn collect_addressed_strings(file: &object::File<'_>) -> BTreeMap<u64, String> {
    let mut output = BTreeMap::new();
    for section in file.sections() {
        if section.kind() == SectionKind::Text {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        addressed_ascii(data, section.address(), &mut output);
        addressed_utf16(data, section.address(), &mut output);
        if output.len() >= MAX_ADDRESSED_STRINGS {
            break;
        }
    }
    output
}

fn build_references(
    file: &object::File<'_>,
    report: &RawReport,
    imports: &[super::ImportRecord],
) -> BTreeMap<u64, ReferenceInfo> {
    let import_slots = imports
        .iter()
        .map(|entry| (entry.iat_address, format!("{}!{}", entry.dll, entry.name)))
        .collect::<BTreeMap<_, _>>();
    let symbols = collect_symbols(file);
    let strings = collect_addressed_strings(file);
    let function_names = report
        .functions
        .iter()
        .map(|function| (function.address, function.name.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut references = BTreeMap::new();
    for function in &report.functions {
        for block in &function.blocks {
            for instruction in &block.instructions {
                references.insert(
                    instruction.address,
                    reference_for_instruction(
                        file,
                        instruction,
                        &report.architecture,
                        &import_slots,
                        &symbols,
                        &strings,
                        &function_names,
                    ),
                );
            }
        }
    }
    references
}

fn is_entry_prologue(
    function: &RawFunction,
    block: &RawBlock,
    index: usize,
    assembly: &str,
) -> bool {
    if block.address != function.address || index > 5 {
        return false;
    }
    let (mnemonic, operands) = split_asm(assembly);
    let mnemonic = mnemonic.to_ascii_lowercase();
    let operands = operands.to_ascii_lowercase().replace(' ', "");
    matches!(
        (mnemonic.as_str(), operands.as_str()),
        ("push", "rbp") | ("mov", "rbp,rsp") | ("mov", "ebp,esp")
    ) || ((mnemonic == "sub" || mnemonic == "and")
        && (operands.starts_with("rsp,") || operands.starts_with("esp,")))
}

fn is_epilogue(block: &RawBlock, index: usize, assembly: &str) -> bool {
    let (mnemonic, operands) = split_asm(assembly);
    let mnemonic = mnemonic.to_ascii_lowercase();
    if mnemonic == "leave" || (mnemonic == "pop" && operands.eq_ignore_ascii_case("rbp")) {
        return block
            .instructions
            .iter()
            .skip(index.saturating_add(1))
            .take(2)
            .any(|instruction| split_asm(&instruction.assembly).0.starts_with("ret"));
    }
    if mnemonic == "add"
        && (operands.to_ascii_lowercase().starts_with("rsp,")
            || operands.to_ascii_lowercase().starts_with("esp,"))
    {
        return block
            .instructions
            .get(index.saturating_add(1))
            .is_some_and(|instruction| split_asm(&instruction.assembly).0.starts_with("ret"));
    }
    false
}

fn readable_statement(
    instruction: &RawInstruction,
    state: &SymbolicState,
    abi: Abi,
    reference: &ReferenceInfo,
    comparison: Option<&Comparison>,
    locals: &mut BTreeSet<String>,
) -> (String, String) {
    let (mnemonic, operands) = split_asm(&instruction.assembly);
    let mnemonic = mnemonic.to_ascii_lowercase();
    let (left, right) = split_operands(operands);
    let memory = reference.memory_reference.as_deref();

    if instruction.control == "return" {
        if let Some(value) = state.regs.get("rax")
            && value != "rax"
        {
            return (format!("return {value};"), "heuristic".to_owned());
        }
        return ("return;".to_owned(), "high".to_owned());
    }

    if instruction.control == "call" {
        let symbol = reference
            .call_symbol
            .as_deref()
            .map(call_display_name)
            .unwrap_or_else(|| "call_indirect".to_owned());
        let args = call_arguments(state, abi);
        let call = if args.is_empty() {
            format!("{symbol}()")
        } else {
            format!("{symbol}({})", args.join(", "))
        };
        return (format!("rax = {call};"), "heuristic".to_owned());
    }

    if instruction.control == "jump" {
        return instruction.target.map_or_else(
            || (format!("goto_indirect({operands});"), "low".to_owned()),
            |target| (format!("goto L_{target:x};"), "high".to_owned()),
        );
    }

    if instruction.control == "conditional" {
        let condition = condition_expression(&mnemonic, comparison);
        return instruction.target.map_or_else(
            || {
                (
                    format!("if ({condition}) goto_indirect({operands});"),
                    "low".to_owned(),
                )
            },
            |target| {
                (
                    format!("if ({condition}) goto L_{target:x};"),
                    if comparison.is_some() {
                        "high"
                    } else {
                        "medium"
                    }
                    .to_owned(),
                )
            },
        );
    }

    let left_value = resolve_operand(left, state, memory, locals);
    let right_value = right.map(|value| resolve_operand(value, state, memory, locals));

    match mnemonic.as_str() {
        "mov" | "movzx" | "movsx" | "movsxd" => right_value.map_or_else(
            || (instruction.pseudocode.clone(), "medium".to_owned()),
            |right| (format!("{left_value} = {right};"), "high".to_owned()),
        ),
        "lea" => right_value.map_or_else(
            || (instruction.pseudocode.clone(), "medium".to_owned()),
            |right| {
                let value = if reference.memory_reference.is_some() {
                    right
                } else {
                    format!("&{right}")
                };
                (format!("{left_value} = {value};"), "high".to_owned())
            },
        ),
        "xor" if right.is_some_and(|right| left.eq_ignore_ascii_case(right)) => {
            (format!("{left_value} = 0;"), "high".to_owned())
        }
        "add" | "sub" | "and" | "or" | "xor" | "shl" | "sal" | "shr" | "sar" | "imul" => {
            let operator = match mnemonic.as_str() {
                "add" => "+",
                "sub" => "-",
                "and" => "&",
                "or" => "|",
                "xor" => "^",
                "shl" | "sal" => "<<",
                "shr" | "sar" => ">>",
                "imul" => "*",
                _ => "?",
            };
            right_value.map_or_else(
                || (instruction.pseudocode.clone(), "medium".to_owned()),
                |right| {
                    let old = canonical_register(left)
                        .and_then(|register| state.regs.get(register))
                        .cloned()
                        .unwrap_or_else(|| left_value.clone());
                    (
                        format!("{left_value} = {old} {operator} {right};"),
                        "high".to_owned(),
                    )
                },
            )
        }
        "inc" => (format!("{left_value} += 1;"), "high".to_owned()),
        "dec" => (format!("{left_value} -= 1;"), "high".to_owned()),
        "cmp" | "test" => (instruction.pseudocode.clone(), "high".to_owned()),
        "nop" => ("/* nop */".to_owned(), "high".to_owned()),
        _ => {
            let mut pseudo = instruction.pseudocode.clone();
            if let Some(local) = stack_variable(operands) {
                locals.insert(local.clone());
                pseudo = pseudo.replace(operands, &local);
            }
            (pseudo, "medium".to_owned())
        }
    }
}

fn enhance_function(
    function: &RawFunction,
    abi: Abi,
    references: &BTreeMap<u64, ReferenceInfo>,
) -> EnhancedFunction {
    let states = compute_states(function, abi, references);
    let mut locals = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut loop_headers = BTreeSet::new();
    for block in &function.blocks {
        for successor in &block.successors {
            if *successor <= block.address {
                loop_headers.insert(*successor);
            }
        }
    }

    let mut blocks = Vec::new();
    for block in &function.blocks {
        let mut state = states.get(&block.address).cloned().unwrap_or_default();
        let mut comparison: Option<Comparison> = None;
        let mut instructions = Vec::new();

        for (index, instruction) in block.instructions.iter().enumerate() {
            let reference = references
                .get(&instruction.address)
                .cloned()
                .unwrap_or_default();
            let (mnemonic, operands) = split_asm(&instruction.assembly);
            let mnemonic_lower = mnemonic.to_ascii_lowercase();
            let (left, right) = split_operands(operands);

            if matches!(mnemonic_lower.as_str(), "cmp" | "test")
                && let Some(right) = right
            {
                let left_value = resolve_operand(
                    left,
                    &state,
                    reference.memory_reference.as_deref(),
                    &mut locals,
                );
                let right_value = resolve_operand(
                    right,
                    &state,
                    reference.memory_reference.as_deref(),
                    &mut locals,
                );
                comparison = Some(Comparison {
                    kind: if mnemonic_lower == "test" {
                        ComparisonKind::Test
                    } else {
                        ComparisonKind::Compare
                    },
                    left: left_value,
                    right: right_value,
                });
            }

            let (pseudocode, confidence) = readable_statement(
                instruction,
                &state,
                abi,
                &reference,
                comparison.as_ref(),
                &mut locals,
            );
            if let Some(symbol) = &reference.call_symbol {
                calls.insert(symbol.clone());
            }

            let hidden = matches!(mnemonic_lower.as_str(), "cmp" | "test" | "nop")
                || is_entry_prologue(function, block, index, &instruction.assembly)
                || is_epilogue(block, index, &instruction.assembly);
            instructions.push(EnhancedInstruction {
                address: instruction.address,
                assembly: instruction.assembly.clone(),
                pseudocode,
                raw_pseudocode: instruction.pseudocode.clone(),
                control: instruction.control.clone(),
                target: instruction.target,
                symbol: reference.call_symbol.clone(),
                memory_reference: reference.memory_reference.clone(),
                confidence,
                hidden_in_readable_output: hidden,
            });
            apply_state(instruction, &mut state, abi, &reference);
        }

        let role = if loop_headers.contains(&block.address) {
            "loop-header"
        } else if block.successors.len() > 1 {
            "branch"
        } else {
            "linear"
        };
        blocks.push(EnhancedBlock {
            address: block.address,
            role: role.to_owned(),
            successors: block.successors.clone(),
            instructions,
        });
    }

    blocks.sort_by_key(|block| block.address);
    for index in 0..blocks.len().saturating_sub(1) {
        let next_address = blocks[index + 1].address;
        if let Some(last) = blocks[index].instructions.last_mut()
            && last.control == "jump"
            && last.target == Some(next_address)
        {
            last.hidden_in_readable_output = true;
            last.pseudocode = "/* natural fallthrough */".to_owned();
        }
    }

    let used_text = blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| !instruction.hidden_in_readable_output)
        .map(|instruction| instruction.pseudocode.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let arguments = abi
        .args
        .iter()
        .enumerate()
        .filter_map(|(index, register)| {
            let name = format!("arg{index}");
            used_text.contains(&name).then(|| ArgumentInfo {
                name,
                register: (*register).to_owned(),
            })
        })
        .collect::<Vec<_>>();
    let returns_value = blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .any(|instruction| {
            instruction.pseudocode.starts_with("return ")
                && instruction.pseudocode.trim() != "return;"
        });

    EnhancedFunction {
        name: function.name.clone(),
        address: function.address,
        size: function.size,
        origin: function.origin.clone(),
        abi: abi.name.to_owned(),
        arguments,
        stack_locals: locals.into_iter().collect(),
        calls: calls.into_iter().collect(),
        loop_headers: loop_headers.into_iter().collect(),
        returns_value,
        blocks,
    }
}

pub(super) fn enhance(data: &[u8], raw: RawReport) -> Result<EnhancedReport, String> {
    let file = object::File::parse(data).map_err(|error| format!("object parse error: {error}"))?;
    let imports = super::pe::imports(data);
    let references = build_references(&file, &raw, &imports);
    let abi = abi_for(&raw);
    let functions = raw
        .functions
        .iter()
        .map(|function| enhance_function(function, abi, &references))
        .collect::<Vec<_>>();

    let mut notes = raw.notes;
    notes.push(
        "v0.5 readability pass performs bounded symbolic register propagation, stack-slot naming, compare/test condition recovery, and natural-fallthrough cleanup.".to_owned(),
    );
    notes.push(
        "Argument names, return expressions, and call arguments are ABI-based heuristics; they are intentionally marked as reconstructed rather than original source.".to_owned(),
    );
    if !imports.is_empty() {
        notes.push(
            "PE import-table entries are mapped to IAT-backed indirect calls when the instruction uses RIP-relative memory.".to_owned(),
        );
    }
    if matches!(
        file.architecture(),
        Architecture::Aarch64 | Architecture::Arm
    ) {
        notes.push(
            "The v0.5 symbolic readability pass currently focuses on x86/x86_64; ARM/AArch64 continues to use the built-in semantic decoder with the common renderer.".to_owned(),
        );
    }

    Ok(EnhancedReport {
        engine: "builtin-native-readable-v0.5".to_owned(),
        format: raw.format,
        architecture: raw.architecture,
        entry: raw.entry,
        sections: raw.sections,
        recovered_strings: raw.recovered_strings,
        imports,
        functions,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_slots_get_readable_names() {
        assert_eq!(
            stack_variable("qword [rbp-20h]"),
            Some("local_20".to_owned())
        );
        assert_eq!(stack_variable("[rsp+0x30]"), Some("stack_30".to_owned()));
    }

    #[test]
    fn conditions_use_previous_compare() {
        let comparison = Comparison {
            kind: ComparisonKind::Compare,
            left: "arg0".to_owned(),
            right: "0".to_owned(),
        };
        assert_eq!(condition_expression("je", Some(&comparison)), "arg0 == 0");
        assert_eq!(condition_expression("jne", Some(&comparison)), "arg0 != 0");
    }

    #[test]
    fn test_register_zero_condition() {
        let comparison = Comparison {
            kind: ComparisonKind::Test,
            left: "rax".to_owned(),
            right: "rax".to_owned(),
        };
        assert_eq!(condition_expression("jz", Some(&comparison)), "rax == 0");
    }

    #[test]
    fn merge_keeps_only_equal_values() {
        let mut left = SymbolicState {
            regs: BTreeMap::from([
                ("rax".to_owned(), "arg0".to_owned()),
                ("rcx".to_owned(), "1".to_owned()),
            ]),
        };
        let right = SymbolicState {
            regs: BTreeMap::from([
                ("rax".to_owned(), "arg0".to_owned()),
                ("rcx".to_owned(), "2".to_owned()),
            ]),
        };
        assert!(merge_state(&mut left, &right));
        assert_eq!(left.regs.get("rax").map(String::as_str), Some("arg0"));
        assert!(!left.regs.contains_key("rcx"));
    }
}
