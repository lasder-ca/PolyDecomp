use super::checked_slice;
use std::fmt::Write as _;

#[derive(Debug, Clone)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

#[derive(Debug, Clone, Default)]
struct Streams {
    strings: Option<(usize, usize)>,
    blob: Option<(usize, usize)>,
    tables: Option<(usize, usize)>,
    version: String,
}

#[derive(Debug, Clone)]
struct TypeDef {
    flags: u32,
    name: String,
    namespace: String,
    method_list: u32,
}

#[derive(Debug, Clone)]
struct MethodDef {
    rva: u32,
    flags: u16,
    name: String,
    signature: u32,
}

fn u16_at(data: &[u8], off: usize) -> Result<u16, String> {
    let b = checked_slice(data, off, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Result<u32, String> {
    let b = checked_slice(data, off, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(data: &[u8], off: usize) -> Result<u64, String> {
    let b = checked_slice(data, off, 8)?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn align4(value: usize) -> usize {
    value.saturating_add(3) & !3
}

fn parse_pe(data: &[u8]) -> Result<(Vec<Section>, u32), String> {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return Err("not a PE file".to_owned());
    }
    let pe = usize::try_from(u32_at(data, 0x3c)?).map_err(|_| "PE offset overflow".to_owned())?;
    if checked_slice(data, pe, 4)? != b"PE\0\0" {
        return Err("invalid PE signature".to_owned());
    }
    let section_count = usize::from(u16_at(data, pe + 6)?);
    if section_count > 256 {
        return Err("PE has too many sections".to_owned());
    }
    let optional_size = usize::from(u16_at(data, pe + 20)?);
    let optional = pe + 24;
    let directories = match u16_at(data, optional)? {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return Err("unsupported PE optional-header format".to_owned()),
    };
    if optional_size < directories.saturating_sub(optional).saturating_add(15 * 8) {
        return Err("PE optional header has no CLR directory".to_owned());
    }
    let clr_rva = u32_at(data, directories + 14 * 8)?;
    if clr_rva == 0 {
        return Err("PE file has no CLR runtime header".to_owned());
    }
    let table = optional + optional_size;
    checked_slice(data, table, section_count.saturating_mul(40))?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let base = table + index * 40;
        sections.push(Section {
            virtual_size: u32_at(data, base + 8)?,
            virtual_address: u32_at(data, base + 12)?,
            raw_size: u32_at(data, base + 16)?,
            raw_offset: u32_at(data, base + 20)?,
        });
    }
    Ok((sections, clr_rva))
}

fn rva_to_offset(sections: &[Section], rva: u32) -> Option<usize> {
    sections.iter().find_map(|section| {
        let span = section.virtual_size.max(section.raw_size);
        (rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span))
            .then(|| usize::try_from(section.raw_offset.saturating_add(rva - section.virtual_address)).ok())
            .flatten()
    })
}

fn parse_streams(data: &[u8], sections: &[Section], clr_rva: u32) -> Result<Streams, String> {
    let clr = rva_to_offset(sections, clr_rva).ok_or_else(|| "CLR header RVA is not mapped".to_owned())?;
    let metadata_rva = u32_at(data, clr + 8)?;
    let metadata = rva_to_offset(sections, metadata_rva).ok_or_else(|| "CLR metadata RVA is not mapped".to_owned())?;
    if u32_at(data, metadata)? != 0x424a_5342 {
        return Err("invalid CLR metadata signature".to_owned());
    }
    let version_len = usize::try_from(u32_at(data, metadata + 12)?).map_err(|_| "CLR version length overflow".to_owned())?;
    if version_len > 4096 {
        return Err("CLR version string too large".to_owned());
    }
    let version = String::from_utf8_lossy(checked_slice(data, metadata + 16, version_len)?)
        .trim_matches('\0')
        .trim()
        .to_owned();
    let header = align4(metadata + 16 + version_len);
    let count = usize::from(u16_at(data, header + 2)?);
    if count > 64 {
        return Err("CLR metadata has too many streams".to_owned());
    }
    let mut streams = Streams {
        version,
        ..Streams::default()
    };
    let mut cursor = header + 4;
    for _ in 0..count {
        let relative = usize::try_from(u32_at(data, cursor)?).map_err(|_| "stream offset overflow".to_owned())?;
        let size = usize::try_from(u32_at(data, cursor + 4)?).map_err(|_| "stream size overflow".to_owned())?;
        cursor += 8;
        let start = cursor;
        while *data.get(cursor).ok_or_else(|| "truncated CLR stream name".to_owned())? != 0 {
            cursor += 1;
            if cursor.saturating_sub(start) > 32 {
                return Err("CLR stream name too long".to_owned());
            }
        }
        let name = String::from_utf8_lossy(&data[start..cursor]).into_owned();
        cursor = align4(cursor + 1);
        let absolute = metadata.checked_add(relative).ok_or_else(|| "CLR stream offset overflow".to_owned())?;
        checked_slice(data, absolute, size)?;
        match name.as_str() {
            "#Strings" => streams.strings = Some((absolute, size)),
            "#Blob" => streams.blob = Some((absolute, size)),
            "#~" | "#-" => streams.tables = Some((absolute, size)),
            _ => {}
        }
    }
    Ok(streams)
}

fn heap_string(data: &[u8], stream: (usize, usize), index: u32) -> String {
    if index == 0 {
        return String::new();
    }
    let Ok(index) = usize::try_from(index) else {
        return "?".to_owned();
    };
    if index >= stream.1 {
        return "?".to_owned();
    }
    let start = stream.0 + index;
    let limit = stream.0 + stream.1;
    let mut end = start;
    while end < limit && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[start..end]).into_owned()
}

fn compressed_uint(data: &[u8], pos: &mut usize, end: usize) -> Result<u32, String> {
    let first = *data
        .get(*pos)
        .filter(|_| *pos < end)
        .ok_or_else(|| "truncated compressed integer".to_owned())?;
    *pos += 1;
    if first & 0x80 == 0 {
        return Ok(u32::from(first));
    }
    if first & 0xc0 == 0x80 {
        let second = *data
            .get(*pos)
            .filter(|_| *pos < end)
            .ok_or_else(|| "truncated compressed integer".to_owned())?;
        *pos += 1;
        return Ok((u32::from(first & 0x3f) << 8) | u32::from(second));
    }
    if first & 0xe0 == 0xc0 {
        let bytes = checked_slice(data, *pos, 3)?;
        if *pos + 3 > end {
            return Err("compressed integer exceeds blob".to_owned());
        }
        *pos += 3;
        return Ok(
            (u32::from(first & 0x1f) << 24)
                | (u32::from(bytes[0]) << 16)
                | (u32::from(bytes[1]) << 8)
                | u32::from(bytes[2]),
        );
    }
    Err("invalid compressed integer".to_owned())
}

fn blob<'a>(data: &'a [u8], stream: (usize, usize), index: u32) -> Result<&'a [u8], String> {
    let index = usize::try_from(index).map_err(|_| "blob index overflow".to_owned())?;
    if index >= stream.1 {
        return Err("blob index outside heap".to_owned());
    }
    let mut pos = stream.0 + index;
    let end = stream.0 + stream.1;
    let len = usize::try_from(compressed_uint(data, &mut pos, end)?).map_err(|_| "blob length overflow".to_owned())?;
    if pos.saturating_add(len) > end {
        return Err("blob exceeds heap".to_owned());
    }
    checked_slice(data, pos, len)
}

fn table_index_size(rows: &[u32; 64], table: usize) -> usize {
    if rows[table] < 65_536 { 2 } else { 4 }
}

fn coded_index_size(rows: &[u32; 64], tables: &[usize], tag_bits: u32) -> usize {
    let max_rows = tables.iter().map(|index| rows[*index]).max().unwrap_or(0);
    if max_rows < (1u32 << (16 - tag_bits)) { 2 } else { 4 }
}

fn read_index(data: &[u8], pos: &mut usize, size: usize) -> Result<u32, String> {
    let value = match size {
        2 => u32::from(u16_at(data, *pos)?),
        4 => u32_at(data, *pos)?,
        _ => return Err("invalid metadata index size".to_owned()),
    };
    *pos += size;
    Ok(value)
}

fn table_row_size(table: usize, rows: &[u32; 64], string_size: usize, guid_size: usize, blob_size: usize) -> Result<usize, String> {
    let simple = |index| table_index_size(rows, index);
    let coded = |tables: &[usize], bits| coded_index_size(rows, tables, bits);
    Ok(match table {
        0 => 2 + string_size + guid_size * 3,
        1 => coded(&[0, 1, 26, 35], 2) + string_size * 2,
        2 => 4 + string_size * 2 + coded(&[2, 1, 27], 2) + simple(4) + simple(6),
        3 => simple(4),
        4 => 2 + string_size + blob_size,
        5 => simple(6),
        6 => 4 + 2 + 2 + string_size + blob_size + simple(8),
        _ => return Err(format!("unsupported metadata table {table} before MethodDef")),
    })
}

fn parse_tables(data: &[u8], streams: &Streams) -> Result<(Vec<TypeDef>, Vec<MethodDef>), String> {
    let strings = streams.strings.ok_or_else(|| "CLR #Strings stream missing".to_owned())?;
    let (tables_off, tables_size) = streams.tables.ok_or_else(|| "CLR tables stream missing".to_owned())?;
    checked_slice(data, tables_off, tables_size)?;
    let heap_sizes = *data.get(tables_off + 6).ok_or_else(|| "truncated CLR tables header".to_owned())?;
    let valid = u64_at(data, tables_off + 8)?;
    let string_size = if heap_sizes & 1 != 0 { 4 } else { 2 };
    let guid_size = if heap_sizes & 2 != 0 { 4 } else { 2 };
    let blob_size = if heap_sizes & 4 != 0 { 4 } else { 2 };
    let mut rows = [0u32; 64];
    let mut cursor = tables_off + 24;
    for (table, row) in rows.iter_mut().enumerate() {
        if valid & (1u64 << table) != 0 {
            *row = u32_at(data, cursor)?;
            cursor += 4;
        }
    }
    let mut types = Vec::new();
    let mut methods = Vec::new();
    for table in 0..=6usize {
        if valid & (1u64 << table) == 0 {
            continue;
        }
        let row_size = table_row_size(table, &rows, string_size, guid_size, blob_size)?;
        let count = usize::try_from(rows[table]).map_err(|_| "metadata row count overflow".to_owned())?;
        let bytes = count.checked_mul(row_size).ok_or_else(|| "metadata table size overflow".to_owned())?;
        checked_slice(data, cursor, bytes)?;
        if table == 2 {
            let extends_size = coded_index_size(&rows, &[2, 1, 27], 2);
            let field_index = table_index_size(&rows, 4);
            let method_index = table_index_size(&rows, 6);
            for _ in 0..count {
                let flags = u32_at(data, cursor)?;
                cursor += 4;
                let name = read_index(data, &mut cursor, string_size)?;
                let namespace = read_index(data, &mut cursor, string_size)?;
                let _extends = read_index(data, &mut cursor, extends_size)?;
                let _fields = read_index(data, &mut cursor, field_index)?;
                let method_list = read_index(data, &mut cursor, method_index)?;
                types.push(TypeDef {
                    flags,
                    name: heap_string(data, strings, name),
                    namespace: heap_string(data, strings, namespace),
                    method_list,
                });
            }
        } else if table == 6 {
            let param_index = table_index_size(&rows, 8);
            for _ in 0..count {
                let rva = u32_at(data, cursor)?;
                cursor += 4;
                let _impl_flags = u16_at(data, cursor)?;
                cursor += 2;
                let flags = u16_at(data, cursor)?;
                cursor += 2;
                let name = read_index(data, &mut cursor, string_size)?;
                let signature = read_index(data, &mut cursor, blob_size)?;
                let _params = read_index(data, &mut cursor, param_index)?;
                methods.push(MethodDef {
                    rva,
                    flags,
                    name: heap_string(data, strings, name),
                    signature,
                });
            }
        } else {
            cursor += bytes;
        }
    }
    Ok((types, methods))
}

fn sig_type(sig: &[u8], pos: &mut usize) -> String {
    let Some(kind) = sig.get(*pos).copied() else {
        return "object".to_owned();
    };
    *pos += 1;
    match kind {
        0x01 => "void".to_owned(),
        0x02 => "bool".to_owned(),
        0x03 => "char".to_owned(),
        0x04 => "sbyte".to_owned(),
        0x05 => "byte".to_owned(),
        0x06 => "short".to_owned(),
        0x07 => "ushort".to_owned(),
        0x08 => "int".to_owned(),
        0x09 => "uint".to_owned(),
        0x0a => "long".to_owned(),
        0x0b => "ulong".to_owned(),
        0x0c => "float".to_owned(),
        0x0d => "double".to_owned(),
        0x0e => "string".to_owned(),
        0x18 => "nint".to_owned(),
        0x19 => "nuint".to_owned(),
        0x1c => "object".to_owned(),
        0x0f => format!("{}*", sig_type(sig, pos)),
        0x10 => format!("ref {}", sig_type(sig, pos)),
        0x1d => format!("{}[]", sig_type(sig, pos)),
        0x11 | 0x12 => {
            let _ = compressed_uint(sig, pos, sig.len());
            "object".to_owned()
        }
        0x13 | 0x1e => format!("T{}", compressed_uint(sig, pos, sig.len()).unwrap_or(0)),
        _ => format!("type_0x{kind:02x}"),
    }
}

fn method_signature(data: &[u8], streams: &Streams, method: &MethodDef) -> String {
    let Some(blob_stream) = streams.blob else {
        return format!("void {}()", method.name);
    };
    let Ok(sig) = blob(data, blob_stream, method.signature) else {
        return format!("void {}()", method.name);
    };
    if sig.is_empty() {
        return format!("void {}()", method.name);
    }
    let mut pos = 1usize;
    if sig[0] & 0x10 != 0 {
        let _ = compressed_uint(sig, &mut pos, sig.len());
    }
    let count = compressed_uint(sig, &mut pos, sig.len()).unwrap_or(0);
    let return_type = sig_type(sig, &mut pos);
    let params = (0..count)
        .map(|index| format!("{} arg{index}", sig_type(sig, &mut pos)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{return_type} {}({params})", method.name)
}

fn method_access(flags: u16) -> String {
    let mut out = Vec::new();
    match flags & 7 {
        1 => out.push("private"),
        2 => out.push("private protected"),
        3 => out.push("internal"),
        4 => out.push("protected"),
        5 => out.push("protected internal"),
        6 => out.push("public"),
        _ => {}
    }
    if flags & 0x10 != 0 { out.push("static"); }
    if flags & 0x40 != 0 { out.push("virtual"); }
    if flags & 0x400 != 0 { out.push("abstract"); }
    if out.is_empty() { String::new() } else { format!("{} ", out.join(" ")) }
}

fn il_name(op: u16) -> &'static str {
    match op {
        0x00 => "nop",
        0x02..=0x05 => "ldarg",
        0x06..=0x09 => "ldloc",
        0x0a..=0x0d => "stloc",
        0x14 => "ldnull",
        0x15..=0x20 => "ldc",
        0x25 => "dup",
        0x26 => "pop",
        0x28 => "call",
        0x2a => "ret",
        0x2b..=0x44 => "branch",
        0x58 => "add",
        0x59 => "sub",
        0x5a => "mul",
        0x5b => "div",
        0x6f => "callvirt",
        0x72 => "ldstr",
        0x73 => "newobj",
        0x7a => "throw",
        0x7b => "ldfld",
        0x7d => "stfld",
        0x8d => "newarr",
        0xd0 => "ldtoken",
        0xfe01 => "ceq",
        0xfe02 => "cgt",
        0xfe04 => "clt",
        _ => "il",
    }
}

fn operand_len(op: u16, code: &[u8], pos: usize) -> usize {
    match op {
        0x0e..=0x13 | 0x1f | 0x2b..=0x37 | 0xde => 1,
        0xfe09..=0xfe0e => 2,
        0x20 | 0x22 | 0x27..=0x29 | 0x38..=0x44 | 0x6f..=0x75 | 0x7b..=0x81 | 0x8c
        | 0x8d | 0xd0 | 0xdd | 0xfe15 | 0xfe16 | 0xfe1c => 4,
        0x21 | 0x23 => 8,
        0x45 if pos + 4 <= code.len() => 4usize.saturating_add(
            usize::try_from(u32::from_le_bytes([code[pos], code[pos + 1], code[pos + 2], code[pos + 3]]))
                .unwrap_or(0)
                .saturating_mul(4),
        ),
        _ => 0,
    }
}

fn disassemble_il(data: &[u8], sections: &[Section], rva: u32) -> String {
    if rva == 0 {
        return "        // no IL body\n".to_owned();
    }
    let Some(offset) = rva_to_offset(sections, rva) else {
        return "        // method RVA is not mapped\n".to_owned();
    };
    let Some(first) = data.get(offset).copied() else {
        return "        // truncated method header\n".to_owned();
    };
    let (header_size, code_size, max_stack) = if first & 3 == 2 {
        (1usize, usize::from(first >> 2), 8u16)
    } else if first & 3 == 3 {
        let Ok(flags_size) = u16_at(data, offset) else {
            return "        // truncated fat method header\n".to_owned();
        };
        let Ok(max_stack) = u16_at(data, offset + 2) else {
            return "        // truncated fat method header\n".to_owned();
        };
        let Ok(code_size) = u32_at(data, offset + 4) else {
            return "        // truncated fat method header\n".to_owned();
        };
        (
            usize::from(flags_size >> 12).saturating_mul(4),
            usize::try_from(code_size).unwrap_or(0),
            max_stack,
        )
    } else {
        return "        // unrecognized IL method header\n".to_owned();
    };
    if code_size > 64 * 1024 * 1024 {
        return "        // IL body exceeds safety limit\n".to_owned();
    }
    let Ok(code) = checked_slice(data, offset + header_size, code_size) else {
        return "        // truncated IL body\n".to_owned();
    };
    let mut out = format!("        // maxstack={max_stack}\n");
    let mut pc = 0usize;
    while pc < code.len() {
        let start = pc;
        let mut op = u16::from(code[pc]);
        pc += 1;
        if op == 0xfe {
            let Some(second) = code.get(pc).copied() else { break; };
            pc += 1;
            op = 0xfe00 | u16::from(second);
        }
        let requested = operand_len(op, code, pc);
        let end = pc.saturating_add(requested).min(code.len());
        let operand = code[pc..end]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(out, "        // IL_{start:04x}: {:<16} {operand}", il_name(op));
        if end == pc && requested != 0 {
            break;
        }
        pc = end;
    }
    out
}

fn type_access(flags: u32) -> &'static str {
    match flags & 7 {
        1 | 2 => "public ",
        3 => "private ",
        4 => "protected ",
        _ => "",
    }
}

pub fn decompile_dotnet(data: &[u8]) -> Result<String, String> {
    let (sections, clr_rva) = parse_pe(data)?;
    let streams = parse_streams(data, &sections, clr_rva)?;
    let (types, methods) = parse_tables(data, &streams)?;
    let mut out = String::new();
    let _ = writeln!(out, "// Decompiled by PolyDecomp built-in .NET engine");
    let _ = writeln!(out, "// CLR metadata version: {}\n", streams.version);
    for (type_index, ty) in types.iter().enumerate() {
        if ty.name == "<Module>" {
            continue;
        }
        if !ty.namespace.is_empty() {
            let _ = writeln!(out, "namespace {} {{", ty.namespace);
        }
        let indent = if ty.namespace.is_empty() { "" } else { "    " };
        let _ = writeln!(out, "{indent}{}class {} {{", type_access(ty.flags), ty.name);
        let start = usize::try_from(ty.method_list.saturating_sub(1)).unwrap_or(0);
        let end = types
            .get(type_index + 1)
            .map(|next| usize::try_from(next.method_list.saturating_sub(1)).unwrap_or(methods.len()))
            .unwrap_or(methods.len())
            .min(methods.len());
        for method in methods.get(start..end).unwrap_or(&[]) {
            let signature = method_signature(data, &streams, method);
            let _ = writeln!(out, "{indent}    {}{signature} {{", method_access(method.flags));
            out.push_str(&disassemble_il(data, &sections, method.rva));
            let _ = writeln!(out, "{indent}    }}\n");
        }
        let _ = writeln!(out, "{indent}}}");
        if !ty.namespace.is_empty() {
            out.push_str("}\n");
        }
        out.push('\n');
    }
    if types.is_empty() {
        out.push_str("// CLR metadata parsed, but no TypeDef rows were found.\n");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_int_one_byte() {
        let data = [0x7f];
        let mut pos = 0;
        assert_eq!(compressed_uint(&data, &mut pos, data.len()).expect("compressed"), 127);
    }

    #[test]
    fn il_names() {
        assert_eq!(il_name(0x28), "call");
        assert_eq!(il_name(0xfe01), "ceq");
    }
}
