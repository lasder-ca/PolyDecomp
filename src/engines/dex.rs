use super::{checked_slice, read_uleb, MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_MEMBER, MAX_ARCHIVE_TOTAL};
use std::fmt::Write as _;
use std::io::{Cursor, Read};
use zip::ZipArchive;

#[derive(Debug, Clone)]
struct DexHeader {
    string_ids_size: usize,
    string_ids_off: usize,
    type_ids_size: usize,
    type_ids_off: usize,
    proto_ids_size: usize,
    proto_ids_off: usize,
    method_ids_size: usize,
    method_ids_off: usize,
    class_defs_size: usize,
    class_defs_off: usize,
}

#[derive(Debug, Clone)]
struct Proto {
    return_type: u32,
    params: Vec<u16>,
}

#[derive(Debug, Clone)]
struct MethodId {
    class_idx: u16,
    proto_idx: u16,
    name_idx: u32,
}

#[derive(Debug, Clone)]
struct EncodedMethod {
    method_idx: u32,
    access: u32,
    code_off: u32,
}

#[derive(Debug, Clone)]
struct ClassDef {
    class_idx: u32,
    access: u32,
    super_idx: u32,
    class_data_off: u32,
}

#[derive(Debug)]
struct DexFile<'a> {
    data: &'a [u8],
    strings: Vec<String>,
    types: Vec<u32>,
    protos: Vec<Proto>,
    methods: Vec<MethodId>,
    classes: Vec<ClassDef>,
}

fn le_u16_at(data: &[u8], off: usize) -> Result<u16, String> {
    let b = checked_slice(data, off, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn le_u32_at(data: &[u8], off: usize) -> Result<u32, String> {
    let b = checked_slice(data, off, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u32_usize(value: u32, what: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{what} does not fit in memory address space"))
}

fn parse_header(data: &[u8]) -> Result<DexHeader, String> {
    if data.len() < 0x70 || !data.starts_with(b"dex\n") {
        return Err("not a DEX file".to_owned());
    }
    let header_size = le_u32_at(data, 0x24)?;
    if header_size < 0x70 {
        return Err("invalid DEX header size".to_owned());
    }
    let endian = le_u32_at(data, 0x28)?;
    if endian != 0x1234_5678 {
        return Err("reverse-endian DEX is not supported".to_owned());
    }
    Ok(DexHeader {
        string_ids_size: u32_usize(le_u32_at(data, 0x38)?, "string_ids_size")?,
        string_ids_off: u32_usize(le_u32_at(data, 0x3c)?, "string_ids_off")?,
        type_ids_size: u32_usize(le_u32_at(data, 0x40)?, "type_ids_size")?,
        type_ids_off: u32_usize(le_u32_at(data, 0x44)?, "type_ids_off")?,
        proto_ids_size: u32_usize(le_u32_at(data, 0x48)?, "proto_ids_size")?,
        proto_ids_off: u32_usize(le_u32_at(data, 0x4c)?, "proto_ids_off")?,
        method_ids_size: u32_usize(le_u32_at(data, 0x58)?, "method_ids_size")?,
        method_ids_off: u32_usize(le_u32_at(data, 0x5c)?, "method_ids_off")?,
        class_defs_size: u32_usize(le_u32_at(data, 0x60)?, "class_defs_size")?,
        class_defs_off: u32_usize(le_u32_at(data, 0x64)?, "class_defs_off")?,
    })
}

fn parse_string(data: &[u8], offset: usize) -> Result<String, String> {
    let mut pos = offset;
    let _utf16_len = read_uleb(data, &mut pos)?;
    let start = pos;
    let mut end = start;
    while let Some(byte) = data.get(end) {
        if *byte == 0 {
            break;
        }
        end += 1;
        if end.saturating_sub(start) > 16 * 1024 * 1024 {
            return Err("DEX string exceeds safety limit".to_owned());
        }
    }
    if end >= data.len() {
        return Err("unterminated DEX string".to_owned());
    }
    Ok(String::from_utf8_lossy(&data[start..end]).into_owned())
}

fn parse_strings(data: &[u8], h: &DexHeader) -> Result<Vec<String>, String> {
    if h.string_ids_size > 2_000_000 {
        return Err("DEX has too many strings".to_owned());
    }
    let table_len = h
        .string_ids_size
        .checked_mul(4)
        .ok_or_else(|| "string table overflow".to_owned())?;
    checked_slice(data, h.string_ids_off, table_len)?;
    let mut out = Vec::with_capacity(h.string_ids_size);
    for i in 0..h.string_ids_size {
        let off = u32_usize(
            le_u32_at(data, h.string_ids_off + i * 4)?,
            "string data offset",
        )?;
        out.push(parse_string(data, off)?);
    }
    Ok(out)
}

fn parse_types(data: &[u8], h: &DexHeader) -> Result<Vec<u32>, String> {
    if h.type_ids_size > 1_000_000 {
        return Err("DEX has too many types".to_owned());
    }
    checked_slice(data, h.type_ids_off, h.type_ids_size.saturating_mul(4))?;
    (0..h.type_ids_size)
        .map(|i| le_u32_at(data, h.type_ids_off + i * 4))
        .collect()
}

fn parse_type_list(data: &[u8], offset: u32) -> Result<Vec<u16>, String> {
    if offset == 0 {
        return Ok(Vec::new());
    }
    let off = u32_usize(offset, "type-list offset")?;
    let count = u32_usize(le_u32_at(data, off)?, "type-list size")?;
    if count > 65_535 {
        return Err("DEX type list too large".to_owned());
    }
    checked_slice(data, off + 4, count.saturating_mul(2))?;
    (0..count)
        .map(|i| le_u16_at(data, off + 4 + i * 2))
        .collect()
}

fn parse_protos(data: &[u8], h: &DexHeader) -> Result<Vec<Proto>, String> {
    if h.proto_ids_size > 1_000_000 {
        return Err("DEX has too many prototypes".to_owned());
    }
    checked_slice(data, h.proto_ids_off, h.proto_ids_size.saturating_mul(12))?;
    let mut out = Vec::with_capacity(h.proto_ids_size);
    for i in 0..h.proto_ids_size {
        let base = h.proto_ids_off + i * 12;
        let return_type = le_u32_at(data, base + 4)?;
        let parameters_off = le_u32_at(data, base + 8)?;
        out.push(Proto {
            return_type,
            params: parse_type_list(data, parameters_off)?,
        });
    }
    Ok(out)
}

fn parse_methods(data: &[u8], h: &DexHeader) -> Result<Vec<MethodId>, String> {
    if h.method_ids_size > 2_000_000 {
        return Err("DEX has too many methods".to_owned());
    }
    checked_slice(data, h.method_ids_off, h.method_ids_size.saturating_mul(8))?;
    let mut out = Vec::with_capacity(h.method_ids_size);
    for i in 0..h.method_ids_size {
        let base = h.method_ids_off + i * 8;
        out.push(MethodId {
            class_idx: le_u16_at(data, base)?,
            proto_idx: le_u16_at(data, base + 2)?,
            name_idx: le_u32_at(data, base + 4)?,
        });
    }
    Ok(out)
}

fn parse_classes(data: &[u8], h: &DexHeader) -> Result<Vec<ClassDef>, String> {
    if h.class_defs_size > 1_000_000 {
        return Err("DEX has too many classes".to_owned());
    }
    checked_slice(data, h.class_defs_off, h.class_defs_size.saturating_mul(32))?;
    let mut out = Vec::with_capacity(h.class_defs_size);
    for i in 0..h.class_defs_size {
        let base = h.class_defs_off + i * 32;
        out.push(ClassDef {
            class_idx: le_u32_at(data, base)?,
            access: le_u32_at(data, base + 4)?,
            super_idx: le_u32_at(data, base + 8)?,
            class_data_off: le_u32_at(data, base + 24)?,
        });
    }
    Ok(out)
}

impl<'a> DexFile<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, String> {
        let h = parse_header(data)?;
        Ok(Self {
            data,
            strings: parse_strings(data, &h)?,
            types: parse_types(data, &h)?,
            protos: parse_protos(data, &h)?,
            methods: parse_methods(data, &h)?,
            classes: parse_classes(data, &h)?,
        })
    }

    fn type_desc(&self, idx: u32) -> &str {
        let Some(string_idx) = self
            .types
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
        else {
            return "Ljava/lang/Object;";
        };
        self.strings
            .get(usize::try_from(*string_idx).unwrap_or(usize::MAX))
            .map(String::as_str)
            .unwrap_or("Ljava/lang/Object;")
    }

    fn string(&self, idx: u32) -> &str {
        self.strings
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .map(String::as_str)
            .unwrap_or("?")
    }

    fn method(&self, idx: u32) -> Option<&MethodId> {
        self.methods.get(usize::try_from(idx).ok()?)
    }
}

fn java_type(desc: &str) -> String {
    let mut arrays = 0usize;
    let mut s = desc;
    while let Some(rest) = s.strip_prefix('[') {
        arrays += 1;
        s = rest;
    }
    let base = match s {
        "V" => "void".to_owned(),
        "Z" => "boolean".to_owned(),
        "B" => "byte".to_owned(),
        "C" => "char".to_owned(),
        "S" => "short".to_owned(),
        "I" => "int".to_owned(),
        "J" => "long".to_owned(),
        "F" => "float".to_owned(),
        "D" => "double".to_owned(),
        _ if s.starts_with('L') && s.ends_with(';') => s[1..s.len() - 1].replace('/', "."),
        _ => s.replace('/', "."),
    };
    format!("{base}{}", "[]".repeat(arrays))
}

fn class_simple(desc: &str) -> String {
    java_type(desc)
        .rsplit('.')
        .next()
        .unwrap_or("Class")
        .to_owned()
}

fn access_words(flags: u32, method: bool) -> String {
    let mut out = Vec::new();
    if flags & 0x1 != 0 {
        out.push("public");
    }
    if flags & 0x2 != 0 {
        out.push("private");
    }
    if flags & 0x4 != 0 {
        out.push("protected");
    }
    if flags & 0x8 != 0 {
        out.push("static");
    }
    if flags & 0x10 != 0 {
        out.push("final");
    }
    if method && flags & 0x20 != 0 {
        out.push("synchronized");
    }
    if flags & 0x100 != 0 {
        out.push("native");
    }
    if flags & 0x400 != 0 {
        out.push("abstract");
    }
    if flags & 0x1000 != 0 {
        out.push("synthetic");
    }
    if out.is_empty() {
        String::new()
    } else {
        format!("{} ", out.join(" "))
    }
}

fn parse_class_data(data: &[u8], offset: u32) -> Result<Vec<EncodedMethod>, String> {
    if offset == 0 {
        return Ok(Vec::new());
    }
    let mut pos = u32_usize(offset, "class-data offset")?;
    let static_fields = read_uleb(data, &mut pos)?;
    let instance_fields = read_uleb(data, &mut pos)?;
    let direct_methods = read_uleb(data, &mut pos)?;
    let virtual_methods = read_uleb(data, &mut pos)?;
    let field_total = static_fields.saturating_add(instance_fields);
    if field_total > 2_000_000 || direct_methods.saturating_add(virtual_methods) > 2_000_000 {
        return Err("DEX class-data section exceeds safety limit".to_owned());
    }
    for _ in 0..field_total {
        let _field_idx_diff = read_uleb(data, &mut pos)?;
        let _access = read_uleb(data, &mut pos)?;
    }
    let mut methods = Vec::new();
    for count in [direct_methods, virtual_methods] {
        let mut method_idx = 0u32;
        for _ in 0..count {
            method_idx = method_idx.saturating_add(read_uleb(data, &mut pos)?);
            let access = read_uleb(data, &mut pos)?;
            let code_off = read_uleb(data, &mut pos)?;
            methods.push(EncodedMethod {
                method_idx,
                access,
                code_off,
            });
        }
    }
    Ok(methods)
}

fn dex_mnemonic(op: u8) -> &'static str {
    match op {
        0x00 => "nop",
        0x01 => "move",
        0x02 => "move/from16",
        0x03 => "move/16",
        0x04 => "move-wide",
        0x05 => "move-wide/from16",
        0x06 => "move-wide/16",
        0x07 => "move-object",
        0x08 => "move-object/from16",
        0x09 => "move-object/16",
        0x0a => "move-result",
        0x0b => "move-result-wide",
        0x0c => "move-result-object",
        0x0d => "move-exception",
        0x0e => "return-void",
        0x0f => "return",
        0x10 => "return-wide",
        0x11 => "return-object",
        0x12 => "const/4",
        0x13 => "const/16",
        0x14 => "const",
        0x15 => "const/high16",
        0x16 => "const-wide/16",
        0x17 => "const-wide/32",
        0x18 => "const-wide",
        0x19 => "const-wide/high16",
        0x1a => "const-string",
        0x1b => "const-string/jumbo",
        0x1c => "const-class",
        0x1d => "monitor-enter",
        0x1e => "monitor-exit",
        0x1f => "check-cast",
        0x20 => "instance-of",
        0x21 => "array-length",
        0x22 => "new-instance",
        0x23 => "new-array",
        0x24 => "filled-new-array",
        0x25 => "filled-new-array/range",
        0x26 => "fill-array-data",
        0x27 => "throw",
        0x28 => "goto",
        0x29 => "goto/16",
        0x2a => "goto/32",
        0x2b => "packed-switch",
        0x2c => "sparse-switch",
        0x2d => "cmpl-float",
        0x2e => "cmpg-float",
        0x2f => "cmpl-double",
        0x30 => "cmpg-double",
        0x31 => "cmp-long",
        0x32 => "if-eq",
        0x33 => "if-ne",
        0x34 => "if-lt",
        0x35 => "if-ge",
        0x36 => "if-gt",
        0x37 => "if-le",
        0x38 => "if-eqz",
        0x39 => "if-nez",
        0x3a => "if-ltz",
        0x3b => "if-gez",
        0x3c => "if-gtz",
        0x3d => "if-lez",
        0x44 => "aget",
        0x45 => "aget-wide",
        0x46 => "aget-object",
        0x47 => "aget-boolean",
        0x48 => "aget-byte",
        0x49 => "aget-char",
        0x4a => "aget-short",
        0x4b => "aput",
        0x4c => "aput-wide",
        0x4d => "aput-object",
        0x52 => "iget",
        0x53 => "iget-wide",
        0x54 => "iget-object",
        0x59 => "iput",
        0x5a => "iput-wide",
        0x5b => "iput-object",
        0x60 => "sget",
        0x61 => "sget-wide",
        0x62 => "sget-object",
        0x67 => "sput",
        0x68 => "sput-wide",
        0x69 => "sput-object",
        0x6e => "invoke-virtual",
        0x6f => "invoke-super",
        0x70 => "invoke-direct",
        0x71 => "invoke-static",
        0x72 => "invoke-interface",
        0x74 => "invoke-virtual/range",
        0x75 => "invoke-super/range",
        0x76 => "invoke-direct/range",
        0x77 => "invoke-static/range",
        0x78 => "invoke-interface/range",
        0x7b => "neg-int",
        0x7c => "not-int",
        0x7d => "neg-long",
        0x7e => "not-long",
        0x7f => "neg-float",
        0x80 => "neg-double",
        0x90 => "add-int",
        0x91 => "sub-int",
        0x92 => "mul-int",
        0x93 => "div-int",
        0x94 => "rem-int",
        0x9b => "add-long",
        0x9c => "sub-long",
        0x9d => "mul-long",
        0xa6 => "add-float",
        0xab => "add-double",
        0xb0 => "add-int/2addr",
        0xb1 => "sub-int/2addr",
        0xb2 => "mul-int/2addr",
        0xd0 => "add-int/lit16",
        0xd1 => "rsub-int",
        0xd2 => "mul-int/lit16",
        0xd8 => "add-int/lit8",
        0xfa => "invoke-polymorphic",
        0xfb => "invoke-polymorphic/range",
        0xfc => "invoke-custom",
        0xfd => "invoke-custom/range",
        0xfe => "const-method-handle",
        0xff => "const-method-type",
        _ => "op",
    }
}

fn dex_len(op: u8) -> usize {
    match op {
        0x02 | 0x05 | 0x08 | 0x13 | 0x15 | 0x16 | 0x19 | 0x1a | 0x1c | 0x1f | 0x20 | 0x22
        | 0x23 | 0x29 | 0x2d..=0x31 | 0x32..=0x3d | 0x44..=0x51 | 0x52..=0x6d
        | 0x90..=0xaf | 0xd0..=0xe2 | 0xfe | 0xff => 2,
        0x03 | 0x06 | 0x09 | 0x14 | 0x17 | 0x1b | 0x24..=0x26 | 0x2a..=0x2c | 0x6e..=0x72
        | 0x74..=0x78 | 0xfc | 0xfd => 3,
        0xfa | 0xfb => 4,
        0x18 => 5,
        _ => 1,
    }
}

fn disassemble_code(data: &[u8], code_off: u32) -> Result<String, String> {
    if code_off == 0 {
        return Ok("        // no code item\n".to_owned());
    }
    let off = u32_usize(code_off, "code offset")?;
    let registers = le_u16_at(data, off)?;
    let ins = le_u16_at(data, off + 2)?;
    let outs = le_u16_at(data, off + 4)?;
    let insns_size = u32_usize(le_u32_at(data, off + 12)?, "instruction count")?;
    if insns_size > 16 * 1024 * 1024 {
        return Err("DEX method has too many code units".to_owned());
    }
    let bytes = checked_slice(data, off + 16, insns_size.saturating_mul(2))?;
    let mut units = Vec::with_capacity(insns_size);
    for chunk in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let mut out = format!("        // registers={registers}, ins={ins}, outs={outs}\n");
    let mut pc = 0usize;
    while pc < units.len() {
        let first = units[pc];
        let op = (first & 0xff) as u8;
        let len = dex_len(op).min(units.len() - pc).max(1);
        let words = units[pc..pc + len]
            .iter()
            .map(|v| format!("{v:04x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            out,
            "        // {pc:04x}: {:<28} {words}",
            dex_mnemonic(op)
        );
        pc += len;
    }
    Ok(out)
}

fn method_signature(dex: &DexFile<'_>, id: &MethodId, access: u32) -> String {
    let name = dex.string(id.name_idx);
    let Some(proto) = dex.protos.get(usize::from(id.proto_idx)) else {
        return format!("{}void {name}()", access_words(access, true));
    };
    let args = proto
        .params
        .iter()
        .enumerate()
        .map(|(i, idx)| format!("{} arg{i}", java_type(dex.type_desc(u32::from(*idx)))))
        .collect::<Vec<_>>()
        .join(", ");
    let ret = java_type(dex.type_desc(proto.return_type));
    format!("{}{ret} {name}({args})", access_words(access, true))
}

fn render_class(dex: &DexFile<'_>, class: &ClassDef) -> Result<(String, String), String> {
    let desc = dex.type_desc(class.class_idx);
    let full = java_type(desc);
    let simple = class_simple(desc);
    let package = full.rsplit_once('.').map(|(p, _)| p);
    let parent = if class.super_idx == u32::MAX {
        None
    } else {
        Some(java_type(dex.type_desc(class.super_idx)))
    };
    let mut out = String::new();
    if let Some(package) = package {
        let _ = writeln!(out, "package {package};\n");
    }
    out.push_str("// Decompiled by PolyDecomp built-in DEX engine\n");
    let _ = write!(out, "{}class {simple}", access_words(class.access, false));
    if let Some(parent) = parent {
        if parent != "java.lang.Object" {
            let _ = write!(out, " extends {parent}");
        }
    }
    out.push_str(" {\n");
    for encoded in parse_class_data(dex.data, class.class_data_off)? {
        let Some(method) = dex.method(encoded.method_idx) else {
            continue;
        };
        if u32::from(method.class_idx) != class.class_idx {
            continue;
        }
        let signature = method_signature(dex, method, encoded.access);
        let _ = writeln!(out, "    {signature} {{");
        match disassemble_code(dex.data, encoded.code_off) {
            Ok(code) => out.push_str(&code),
            Err(error) => {
                let _ = writeln!(out, "        // code parse error: {error}");
            }
        }
        out.push_str("    }\n\n");
    }
    out.push_str("}\n");
    let path = full.replace('.', "/") + ".java";
    Ok((path, out))
}

pub fn decompile_dex(data: &[u8]) -> Result<Vec<(String, String)>, String> {
    let dex = DexFile::parse(data)?;
    let mut out = Vec::new();
    for class in &dex.classes {
        out.push(render_class(&dex, class)?);
    }
    if out.is_empty() {
        out.push((
            "DexSummary.txt".to_owned(),
            format!(
                "DEX parsed successfully\nstrings={}\ntypes={}\nprototypes={}\nmethods={}\nclasses=0\n",
                dex.strings.len(),
                dex.types.len(),
                dex.protos.len(),
                dex.methods.len()
            ),
        ));
    }
    Ok(out)
}

fn safe_name(name: &str) -> String {
    name.replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/")
}

pub fn decompile_apk(data: &[u8]) -> Result<Vec<(String, String)>, String> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| format!("invalid APK: {e}"))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err("APK contains too many entries".to_owned());
    }
    let mut dex_blobs = Vec::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| format!("APK entry error: {e}"))?;
        let name = safe_name(entry.name());
        let base = name.rsplit('/').next().unwrap_or(&name);
        if !base.starts_with("classes") || !base.ends_with(".dex") {
            continue;
        }
        if entry.size() > MAX_ARCHIVE_MEMBER {
            return Err("APK DEX exceeds safety limit".to_owned());
        }
        total = total.saturating_add(entry.size());
        if total > MAX_ARCHIVE_TOTAL {
            return Err("APK expanded DEX size exceeds safety limit".to_owned());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("APK read error: {e}"))?;
        dex_blobs.push((base.to_owned(), bytes));
    }
    if dex_blobs.is_empty() {
        return Err("APK contains no classes*.dex".to_owned());
    }
    let mut outputs = Vec::new();
    for (dex_name, bytes) in dex_blobs {
        match decompile_dex(&bytes) {
            Ok(files) => {
                for (name, content) in files {
                    outputs.push((
                        format!("{}/{}", dex_name.trim_end_matches(".dex"), name),
                        content,
                    ));
                }
            }
            Err(error) => outputs.push((format!("{dex_name}.error.txt"), error)),
        }
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_conversion() {
        assert_eq!(java_type("Ljava/lang/String;"), "java.lang.String");
        assert_eq!(java_type("[[I"), "int[][]");
    }

    #[test]
    fn uleb_class_data_helper() {
        let bytes = [0x81, 0x01];
        let mut pos = 0;
        assert_eq!(read_uleb(&bytes, &mut pos).expect("uleb"), 129);
    }
}
