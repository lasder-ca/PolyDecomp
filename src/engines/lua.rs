use super::{Reader, printable_strings};
use std::fmt::Write as _;

#[derive(Clone, Copy)]
struct Lua51Header {
    little: bool,
    int_size: usize,
    size_t_size: usize,
    instruction_size: usize,
    number_size: usize,
}

fn read_uint(reader: &mut Reader<'_>, size: usize, little: bool) -> Result<u64, String> {
    let bytes = reader.take(size)?;
    let mut out = 0u64;
    if little {
        for (i, byte) in bytes.iter().copied().enumerate() {
            if i >= 8 {
                break;
            }
            out |= u64::from(byte) << (i * 8);
        }
    } else {
        for byte in bytes.iter().copied().take(8) {
            out = (out << 8) | u64::from(byte);
        }
    }
    Ok(out)
}

fn read_lua_string(reader: &mut Reader<'_>, h: Lua51Header) -> Result<String, String> {
    let len = usize::try_from(read_uint(reader, h.size_t_size, h.little)?)
        .map_err(|_| "Lua string length overflow".to_owned())?;
    if len == 0 {
        return Ok(String::new());
    }
    if len > 64 * 1024 * 1024 {
        return Err("Lua string exceeds safety limit".to_owned());
    }
    let bytes = reader.take(len)?;
    let body = if bytes.last() == Some(&0) {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    Ok(String::from_utf8_lossy(body).into_owned())
}

fn lua51_mnemonic(op: u32) -> &'static str {
    const OPS: [&str; 38] = [
        "MOVE",
        "LOADK",
        "LOADBOOL",
        "LOADNIL",
        "GETUPVAL",
        "GETGLOBAL",
        "GETTABLE",
        "SETGLOBAL",
        "SETUPVAL",
        "SETTABLE",
        "NEWTABLE",
        "SELF",
        "ADD",
        "SUB",
        "MUL",
        "DIV",
        "MOD",
        "POW",
        "UNM",
        "NOT",
        "LEN",
        "CONCAT",
        "JMP",
        "EQ",
        "LT",
        "LE",
        "TEST",
        "TESTSET",
        "CALL",
        "TAILCALL",
        "RETURN",
        "FORLOOP",
        "FORPREP",
        "TFORLOOP",
        "SETLIST",
        "CLOSE",
        "CLOSURE",
        "VARARG",
    ];
    OPS.get(op as usize).copied().unwrap_or("OP")
}

fn decode_lua51(instruction: u32) -> String {
    let op = instruction & 0x3f;
    let a = (instruction >> 6) & 0xff;
    let c = (instruction >> 14) & 0x1ff;
    let b = (instruction >> 23) & 0x1ff;
    let bx = (instruction >> 14) & 0x3ffff;
    let sbx = i32::try_from(bx).unwrap_or(i32::MAX) - 131_071;
    let name = lua51_mnemonic(op);
    match op {
        1 | 5 | 7 | 36 => format!("{name:<10} A={a} Bx={bx}"),
        22 | 31 | 32 => format!("{name:<10} A={a} sBx={sbx:+}"),
        0 | 2..=4 | 6 | 8..=21 | 23..=30 | 33..=35 | 37 => format!("{name:<10} A={a} B={b} C={c}"),
        _ => format!("{name:<10} raw=0x{instruction:08x}"),
    }
}

fn parse_lua51_function(
    reader: &mut Reader<'_>,
    h: Lua51Header,
    depth: usize,
    out: &mut String,
) -> Result<(), String> {
    if depth > 100 {
        return Err("Lua prototype nesting exceeds safety limit".to_owned());
    }
    let source = read_lua_string(reader, h)?;
    let line_defined = read_uint(reader, h.int_size, h.little)?;
    let last_line = read_uint(reader, h.int_size, h.little)?;
    let nups = reader.u8()?;
    let params = reader.u8()?;
    let vararg = reader.u8()?;
    let maxstack = reader.u8()?;
    let indent = "    ".repeat(depth);
    let _ = writeln!(
        out,
        "{indent}function proto_{depth}(...)  -- source={source:?}, lines={line_defined}..{last_line}, upvalues={nups}, params={params}, vararg={vararg}, stack={maxstack}"
    );
    let code_count = usize::try_from(read_uint(reader, h.int_size, h.little)?)
        .map_err(|_| "Lua code count overflow".to_owned())?;
    if code_count > 16 * 1024 * 1024 {
        return Err("Lua code section exceeds safety limit".to_owned());
    }
    for pc in 0..code_count {
        let raw = read_uint(reader, h.instruction_size, h.little)? as u32;
        let _ = writeln!(out, "{indent}    -- {pc:04}: {}", decode_lua51(raw));
    }
    let constant_count = usize::try_from(read_uint(reader, h.int_size, h.little)?)
        .map_err(|_| "Lua constant count overflow".to_owned())?;
    if constant_count > 2_000_000 {
        return Err("Lua constant pool exceeds safety limit".to_owned());
    }
    for i in 0..constant_count {
        let kind = reader.u8()?;
        let value = match kind {
            0 => "nil".to_owned(),
            1 => (reader.u8()? != 0).to_string(),
            3 => {
                let bits = read_uint(reader, h.number_size, h.little)?;
                if h.number_size == 8 {
                    f64::from_bits(bits).to_string()
                } else {
                    format!("number(0x{bits:x})")
                }
            }
            4 => format!("{:?}", read_lua_string(reader, h)?),
            _ => return Err(format!("unknown Lua 5.1 constant type {kind}")),
        };
        let _ = writeln!(out, "{indent}    -- const[{i}] = {value}");
    }
    let proto_count = usize::try_from(read_uint(reader, h.int_size, h.little)?)
        .map_err(|_| "Lua prototype count overflow".to_owned())?;
    if proto_count > 100_000 {
        return Err("Lua prototype count exceeds safety limit".to_owned());
    }
    for _ in 0..proto_count {
        parse_lua51_function(reader, h, depth + 1, out)?;
    }
    let line_count = usize::try_from(read_uint(reader, h.int_size, h.little)?)
        .map_err(|_| "Lua lineinfo overflow".to_owned())?;
    reader.skip(line_count.saturating_mul(h.int_size))?;
    let local_count = usize::try_from(read_uint(reader, h.int_size, h.little)?)
        .map_err(|_| "Lua locals overflow".to_owned())?;
    for _ in 0..local_count {
        let _ = read_lua_string(reader, h)?;
        reader.skip(h.int_size.saturating_mul(2))?;
    }
    let upvalue_count = usize::try_from(read_uint(reader, h.int_size, h.little)?)
        .map_err(|_| "Lua upvalues overflow".to_owned())?;
    for _ in 0..upvalue_count {
        let _ = read_lua_string(reader, h)?;
    }
    let _ = writeln!(out, "{indent}end\n");
    Ok(())
}

fn decompile_lua51(data: &[u8]) -> Result<String, String> {
    let mut r = Reader::new(data);
    if r.take(4)? != b"\x1bLua" {
        return Err("not Lua bytecode".to_owned());
    }
    let version = r.u8()?;
    if version != 0x51 {
        return Err("not Lua 5.1".to_owned());
    }
    let format = r.u8()?;
    if format != 0 {
        return Err("unsupported Lua 5.1 binary format".to_owned());
    }
    let little = match r.u8()? {
        1 => true,
        0 => false,
        _ => return Err("invalid Lua endianness".to_owned()),
    };
    let h = Lua51Header {
        little,
        int_size: usize::from(r.u8()?),
        size_t_size: usize::from(r.u8()?),
        instruction_size: usize::from(r.u8()?),
        number_size: usize::from(r.u8()?),
    };
    let _integral = r.u8()?;
    if !matches!(h.int_size, 4 | 8)
        || !matches!(h.size_t_size, 4 | 8)
        || h.instruction_size != 4
        || !matches!(h.number_size, 4 | 8)
    {
        return Err("unsupported Lua 5.1 numeric layout".to_owned());
    }
    let mut out = String::from("-- Decompiled by PolyDecomp built-in Lua 5.1 engine\n");
    parse_lua51_function(&mut r, h, 0, &mut out)?;
    Ok(out)
}

pub fn decompile_lua(data: &[u8]) -> Result<String, String> {
    if data.len() < 6 || !data.starts_with(b"\x1bLua") {
        return Err("not Lua bytecode".to_owned());
    }
    let version = data[4];
    if version == 0x51 {
        return decompile_lua51(data);
    }
    let version_text = match version {
        0x52 => "5.2",
        0x53 => "5.3",
        0x54 => "5.4",
        _ => "unknown",
    };
    let mut out = format!(
        "-- PolyDecomp built-in Lua bytecode report\n-- Lua version: {version_text} (0x{version:02x})\n"
    );
    out.push_str("-- This version uses a different prototype layout; recovered strings and instruction candidates follow.\n\n");
    for (i, value) in printable_strings(data, 4, 10_000).into_iter().enumerate() {
        let _ = writeln!(out, "-- string[{i}] = {value:?}");
    }
    out.push_str("\n-- 32-bit instruction candidates (little-endian):\n");
    let start = if data.len() > 32 { 32 } else { 6 };
    for (i, chunk) in data[start..]
        .as_chunks::<4>()
        .0
        .iter()
        .take(200_000)
        .enumerate()
    {
        let raw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let _ = writeln!(out, "-- {:06x}: 0x{raw:08x}", start + i * 4);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lua51_instruction_decode() {
        assert!(decode_lua51(0).contains("MOVE"));
    }

    #[test]
    fn rejects_text_lua() {
        assert!(decompile_lua(b"print('x')").is_err());
    }
}
