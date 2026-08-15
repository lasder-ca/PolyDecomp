use super::{MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_MEMBER, MAX_ARCHIVE_TOTAL, Reader};
use std::fmt::Write as _;
use std::io::{Cursor, Read};
use zip::ZipArchive;

#[derive(Clone, Debug)]
enum Cp {
    Empty,
    Utf8(String),
    Class(u16),
    String(u16),
    Ref(u16, u16),
    NameType(u16, u16),
    Number(String),
}

fn cp_utf8(cp: &[Cp], index: u16) -> Option<&str> {
    match cp.get(usize::from(index))? {
        Cp::Utf8(value) => Some(value),
        _ => None,
    }
}

fn cp_class(cp: &[Cp], index: u16) -> Option<String> {
    match cp.get(usize::from(index))? {
        Cp::Class(name) => cp_utf8(cp, *name).map(|value| value.replace('/', ".")),
        _ => None,
    }
}

fn cp_text(cp: &[Cp], index: u16) -> String {
    match cp.get(usize::from(index)) {
        Some(Cp::Utf8(value)) => format!("{value:?}"),
        Some(Cp::Class(_)) => cp_class(cp, index).unwrap_or_else(|| format!("#{index}")),
        Some(Cp::String(string_index)) => cp_utf8(cp, *string_index)
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|| format!("#{string_index}")),
        Some(Cp::Number(value)) => value.clone(),
        Some(Cp::NameType(name, descriptor)) => format!(
            "{}:{}",
            cp_utf8(cp, *name).unwrap_or("?"),
            cp_utf8(cp, *descriptor).unwrap_or("?")
        ),
        Some(Cp::Ref(class, name_type)) => format!(
            "{}.{}",
            cp_class(cp, *class).unwrap_or_else(|| "?".to_owned()),
            cp_text(cp, *name_type)
        ),
        _ => format!("#{index}"),
    }
}

fn parse_constant_pool(reader: &mut Reader<'_>) -> Result<Vec<Cp>, String> {
    let count = usize::from(reader.be_u16()?);
    if count == 0 || count > 65_535 {
        return Err("invalid JVM constant-pool size".to_owned());
    }
    let mut cp = vec![Cp::Empty];
    let mut index = 1usize;
    while index < count {
        let tag = reader.u8()?;
        let item = match tag {
            1 => {
                let len = usize::from(reader.be_u16()?);
                Cp::Utf8(String::from_utf8_lossy(reader.take(len)?).into_owned())
            }
            3 => Cp::Number((reader.be_u32()? as i32).to_string()),
            4 => Cp::Number(f32::from_bits(reader.be_u32()?).to_string()),
            5 => {
                let high = u64::from(reader.be_u32()?);
                let low = u64::from(reader.be_u32()?);
                cp.push(Cp::Number(((high << 32 | low) as i64).to_string()));
                cp.push(Cp::Empty);
                index += 2;
                continue;
            }
            6 => {
                let high = u64::from(reader.be_u32()?);
                let low = u64::from(reader.be_u32()?);
                cp.push(Cp::Number(f64::from_bits(high << 32 | low).to_string()));
                cp.push(Cp::Empty);
                index += 2;
                continue;
            }
            7 => Cp::Class(reader.be_u16()?),
            8 => Cp::String(reader.be_u16()?),
            9..=11 => Cp::Ref(reader.be_u16()?, reader.be_u16()?),
            12 => Cp::NameType(reader.be_u16()?, reader.be_u16()?),
            15 => {
                reader.skip(3)?;
                Cp::Empty
            }
            16 | 19 | 20 => {
                reader.skip(2)?;
                Cp::Empty
            }
            17 | 18 => {
                reader.skip(4)?;
                Cp::Empty
            }
            _ => return Err(format!("unsupported JVM constant-pool tag {tag}")),
        };
        cp.push(item);
        index += 1;
    }
    if cp.len() != count {
        return Err("malformed JVM constant pool".to_owned());
    }
    Ok(cp)
}

fn skip_attributes(reader: &mut Reader<'_>) -> Result<(), String> {
    let count = reader.be_u16()?;
    for _ in 0..count {
        reader.skip(2)?;
        let len = usize::try_from(reader.be_u32()?)
            .map_err(|_| "JVM attribute length overflow".to_owned())?;
        reader.skip(len)?;
    }
    Ok(())
}

fn parse_type(descriptor: &str, position: &mut usize) -> String {
    let bytes = descriptor.as_bytes();
    let mut arrays = 0usize;
    while bytes.get(*position) == Some(&b'[') {
        arrays += 1;
        *position += 1;
    }
    let base = match bytes.get(*position).copied() {
        Some(b'V') => "void".to_owned(),
        Some(b'Z') => "boolean".to_owned(),
        Some(b'B') => "byte".to_owned(),
        Some(b'C') => "char".to_owned(),
        Some(b'S') => "short".to_owned(),
        Some(b'I') => "int".to_owned(),
        Some(b'J') => "long".to_owned(),
        Some(b'F') => "float".to_owned(),
        Some(b'D') => "double".to_owned(),
        Some(b'L') => {
            *position += 1;
            let start = *position;
            while bytes.get(*position).is_some_and(|value| *value != b';') {
                *position += 1;
            }
            descriptor
                .get(start..*position)
                .unwrap_or("Object")
                .replace('/', ".")
        }
        _ => "Object".to_owned(),
    };
    *position = position.saturating_add(1).min(bytes.len());
    format!("{base}{}", "[]".repeat(arrays))
}

fn method_descriptor(descriptor: &str) -> (Vec<String>, String) {
    let mut position = usize::from(descriptor.starts_with('('));
    let mut args = Vec::new();
    while descriptor
        .as_bytes()
        .get(position)
        .is_some_and(|value| *value != b')')
    {
        args.push(parse_type(descriptor, &mut position));
    }
    if descriptor.as_bytes().get(position) == Some(&b')') {
        position += 1;
    }
    (args, parse_type(descriptor, &mut position))
}

fn modifiers(flags: u16) -> String {
    let mut words = Vec::new();
    if flags & 0x0001 != 0 {
        words.push("public");
    }
    if flags & 0x0002 != 0 {
        words.push("private");
    }
    if flags & 0x0004 != 0 {
        words.push("protected");
    }
    if flags & 0x0008 != 0 {
        words.push("static");
    }
    if flags & 0x0010 != 0 {
        words.push("final");
    }
    if flags & 0x0100 != 0 {
        words.push("native");
    }
    if flags & 0x0400 != 0 {
        words.push("abstract");
    }
    if words.is_empty() {
        String::new()
    } else {
        format!("{} ", words.join(" "))
    }
}

fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "nop",
        0x01 => "aconst_null",
        0x02..=0x08 => "iconst",
        0x10 => "bipush",
        0x11 => "sipush",
        0x12..=0x14 => "ldc",
        0x15..=0x19 => "load",
        0x36..=0x3a => "store",
        0x57 => "pop",
        0x59 => "dup",
        0x60 => "iadd",
        0x64 => "isub",
        0x68 => "imul",
        0x6c => "idiv",
        0x84 => "iinc",
        0x99..=0xa6 => "if",
        0xa7 => "goto",
        0xaa => "tableswitch",
        0xab => "lookupswitch",
        0xac..=0xb1 => "return",
        0xb2 => "getstatic",
        0xb3 => "putstatic",
        0xb4 => "getfield",
        0xb5 => "putfield",
        0xb6 => "invokevirtual",
        0xb7 => "invokespecial",
        0xb8 => "invokestatic",
        0xb9 => "invokeinterface",
        0xba => "invokedynamic",
        0xbb => "new",
        0xbd => "anewarray",
        0xbf => "athrow",
        0xc0 => "checkcast",
        0xc1 => "instanceof",
        0xc4 => "wide",
        _ => "op",
    }
}

fn fixed_instruction_len(opcode: u8) -> usize {
    match opcode {
        0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3a | 0xa9 | 0xbc => 2,
        0x11
        | 0x13
        | 0x14
        | 0x84
        | 0x99..=0xa8
        | 0xb2..=0xb8
        | 0xbb
        | 0xbd
        | 0xc0
        | 0xc1
        | 0xc6
        | 0xc7 => 3,
        0xc5 => 4,
        0xb9 | 0xba | 0xc8 | 0xc9 => 5,
        _ => 1,
    }
}

fn be_i32(code: &[u8], offset: usize) -> Option<i32> {
    let bytes = code.get(offset..offset + 4)?;
    Some(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn instruction_len(code: &[u8], pc: usize) -> usize {
    let Some(opcode) = code.get(pc).copied() else {
        return 1;
    };
    match opcode {
        0xaa => {
            let padding = (4 - ((pc + 1) & 3)) & 3;
            let base = pc + 1 + padding;
            let Some(low) = be_i32(code, base + 4) else {
                return code.len() - pc;
            };
            let Some(high) = be_i32(code, base + 8) else {
                return code.len() - pc;
            };
            let entries = high.saturating_sub(low).saturating_add(1).max(0) as usize;
            1usize
                .saturating_add(padding)
                .saturating_add(12)
                .saturating_add(entries.saturating_mul(4))
        }
        0xab => {
            let padding = (4 - ((pc + 1) & 3)) & 3;
            let base = pc + 1 + padding;
            let Some(pairs) = be_i32(code, base + 4) else {
                return code.len() - pc;
            };
            1usize
                .saturating_add(padding)
                .saturating_add(8)
                .saturating_add((pairs.max(0) as usize).saturating_mul(8))
        }
        0xc4 => match code.get(pc + 1).copied() {
            Some(0x84) => 6,
            Some(_) => 4,
            None => 1,
        },
        _ => fixed_instruction_len(opcode),
    }
}

fn code_text(code: &[u8], cp: &[Cp]) -> String {
    let mut out = String::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let opcode = code[pc];
        let requested = instruction_len(code, pc).max(1);
        let end = pc.saturating_add(requested).min(code.len());
        let operands = &code[pc + 1..end];
        let detail = if opcode == 0x12 {
            operands
                .first()
                .map(|index| cp_text(cp, u16::from(*index)))
                .unwrap_or_default()
        } else if matches!(
            opcode,
            0x13 | 0x14 | 0xb2..=0xb9 | 0xbb | 0xbd | 0xc0 | 0xc1
        ) && operands.len() >= 2
        {
            cp_text(cp, u16::from_be_bytes([operands[0], operands[1]]))
        } else {
            operands
                .iter()
                .take(32)
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let _ = writeln!(
            out,
            "        // {pc:04x}: {:<20} {detail}",
            opcode_name(opcode)
        );
        if end == code.len() && requested > end.saturating_sub(pc) {
            break;
        }
        pc = end;
    }
    out
}

pub fn decompile_class(data: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(data);
    if reader.be_u32()? != 0xcafe_babe {
        return Err("not a JVM class".to_owned());
    }
    let _minor = reader.be_u16()?;
    let major = reader.be_u16()?;
    let cp = parse_constant_pool(&mut reader)?;
    let access = reader.be_u16()?;
    let this_class = reader.be_u16()?;
    let super_class = reader.be_u16()?;
    let class_name =
        cp_class(&cp, this_class).ok_or_else(|| "invalid JVM class name".to_owned())?;
    let parent = if super_class == 0 {
        None
    } else {
        cp_class(&cp, super_class)
    };

    let interface_count = usize::from(reader.be_u16()?);
    let mut interfaces = Vec::with_capacity(interface_count);
    for _ in 0..interface_count {
        if let Some(name) = cp_class(&cp, reader.be_u16()?) {
            interfaces.push(name);
        }
    }

    let simple = class_name.rsplit('.').next().unwrap_or(&class_name);
    let mut out = String::new();
    if let Some((package, _)) = class_name.rsplit_once('.') {
        let _ = writeln!(out, "package {package};\n");
    }
    let kind = if access & 0x0200 != 0 {
        "interface"
    } else if access & 0x4000 != 0 {
        "enum"
    } else {
        "class"
    };
    let _ = write!(
        out,
        "// Decompiled by PolyDecomp built-in JVM engine; class version {major}\n{}{kind} {simple}",
        modifiers(access)
    );
    if kind == "class"
        && let Some(parent) = parent
        && parent != "java.lang.Object"
    {
        let _ = write!(out, " extends {parent}");
    }
    if !interfaces.is_empty() {
        let keyword = if kind == "interface" {
            "extends"
        } else {
            "implements"
        };
        let _ = write!(out, " {keyword} {}", interfaces.join(", "));
    }
    out.push_str(" {\n");

    let field_count = reader.be_u16()?;
    for _ in 0..field_count {
        let flags = reader.be_u16()?;
        let name = cp_utf8(&cp, reader.be_u16()?).unwrap_or("field").to_owned();
        let descriptor = cp_utf8(&cp, reader.be_u16()?)
            .unwrap_or("Ljava/lang/Object;")
            .to_owned();
        skip_attributes(&mut reader)?;
        let mut position = 0usize;
        let _ = writeln!(
            out,
            "    {}{} {name};",
            modifiers(flags),
            parse_type(&descriptor, &mut position)
        );
    }

    let method_count = reader.be_u16()?;
    for _ in 0..method_count {
        let flags = reader.be_u16()?;
        let name = cp_utf8(&cp, reader.be_u16()?)
            .unwrap_or("method")
            .to_owned();
        let descriptor = cp_utf8(&cp, reader.be_u16()?).unwrap_or("()V").to_owned();
        let attribute_count = reader.be_u16()?;
        let mut body = None;
        let mut max_stack = 0u16;
        let mut max_locals = 0u16;
        for _ in 0..attribute_count {
            let attribute_name = cp_utf8(&cp, reader.be_u16()?).unwrap_or("").to_owned();
            let length = usize::try_from(reader.be_u32()?)
                .map_err(|_| "JVM attribute length overflow".to_owned())?;
            if attribute_name == "Code" {
                let start = reader.position();
                max_stack = reader.be_u16()?;
                max_locals = reader.be_u16()?;
                let code_len = usize::try_from(reader.be_u32()?)
                    .map_err(|_| "JVM method size overflow".to_owned())?;
                if code_len > 64 * 1024 * 1024 {
                    return Err("JVM method exceeds safety limit".to_owned());
                }
                body = Some(reader.take(code_len)?.to_vec());
                let exception_count = usize::from(reader.be_u16()?);
                reader.skip(exception_count.saturating_mul(8))?;
                skip_attributes(&mut reader)?;
                let used = reader.position().saturating_sub(start);
                if used > length {
                    return Err("JVM Code attribute length mismatch".to_owned());
                }
                if used < length {
                    reader.skip(length - used)?;
                }
            } else {
                reader.skip(length)?;
            }
        }

        let (args, return_type) = method_descriptor(&descriptor);
        let params = args
            .iter()
            .enumerate()
            .map(|(index, ty)| format!("{ty} arg{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        if name == "<clinit>" {
            out.push_str("\n    static {\n");
        } else if name == "<init>" {
            let _ = writeln!(out, "\n    {}{simple}({params}) {{", modifiers(flags));
        } else {
            let _ = writeln!(
                out,
                "\n    {}{return_type} {name}({params}) {{",
                modifiers(flags)
            );
        }
        if let Some(code) = body {
            let _ = writeln!(
                out,
                "        // max_stack={max_stack}, max_locals={max_locals}"
            );
            out.push_str(&code_text(&code, &cp));
        } else {
            out.push_str("        // abstract/native method: no Code attribute\n");
        }
        out.push_str("    }\n");
    }

    skip_attributes(&mut reader)?;
    out.push_str("}\n");
    Ok(out)
}

fn safe_name(name: &str) -> String {
    name.replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/")
}

pub fn decompile_jar(data: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut archive =
        ZipArchive::new(Cursor::new(data)).map_err(|error| format!("invalid JAR: {error}"))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err("JAR contains too many entries".to_owned());
    }
    let mut total = 0u64;
    let mut output = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| error.to_string())?;
        if entry.is_dir() || !entry.name().ends_with(".class") {
            continue;
        }
        if entry.size() > MAX_ARCHIVE_MEMBER {
            return Err("JAR class exceeds safety limit".to_owned());
        }
        total = total.saturating_add(entry.size());
        if total > MAX_ARCHIVE_TOTAL {
            return Err("JAR expanded size exceeds safety limit".to_owned());
        }
        let output_name = format!(
            "{}.java",
            safe_name(entry.name()).trim_end_matches(".class")
        );
        let mut bytes = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
        entry
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        let source = decompile_class(&bytes)
            .unwrap_or_else(|error| format!("// class parse failed: {error}\n"));
        output.push((output_name, source));
    }
    if output.is_empty() {
        Err("JAR contains no class files".to_owned())
    } else {
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_parser() {
        let (args, result) = method_descriptor("(ILjava/lang/String;[B)V");
        assert_eq!(args, ["int", "java.lang.String", "byte[]"]);
        assert_eq!(result, "void");
    }

    #[test]
    fn opcode_names() {
        assert_eq!(opcode_name(0xb6), "invokevirtual");
        assert_eq!(opcode_name(0xaa), "tableswitch");
    }
}
