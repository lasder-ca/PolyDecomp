use super::Reader;
use std::fmt::Write as _;

#[derive(Debug, Clone)]
enum Obj {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Str(String),
    Tuple(Vec<Obj>),
    List(Vec<Obj>),
    Dict(Vec<(Obj, Obj)>),
    Code(CodeObj),
    Other(String),
}

#[derive(Debug, Clone)]
struct CodeObj {
    argcount: u32,
    posonlyargcount: u32,
    kwonlyargcount: u32,
    stacksize: u32,
    flags: u32,
    code: Vec<u8>,
    consts: Vec<Obj>,
    names: Vec<String>,
    locals: Vec<String>,
    filename: String,
    name: String,
    qualname: String,
    firstlineno: u32,
}

struct MarshalReader<'a> {
    r: Reader<'a>,
    refs: Vec<Obj>,
    modern_code: bool,
    depth: usize,
}

impl<'a> MarshalReader<'a> {
    fn new(data: &'a [u8], modern_code: bool) -> Self {
        Self { r: Reader::new(data), refs: Vec::new(), modern_code, depth: 0 }
    }

    fn i32(&mut self) -> Result<i32, String> { Ok(self.r.le_u32()? as i32) }

    fn i64(&mut self) -> Result<i64, String> { Ok(self.r.le_u64()? as i64) }

    fn len(&mut self, limit: usize) -> Result<usize, String> {
        let value = self.i32()?;
        if value < 0 { return Err("negative marshal length".to_owned()); }
        let value = usize::try_from(value).map_err(|_| "marshal length overflow".to_owned())?;
        if value > limit { return Err("marshal object exceeds safety limit".to_owned()); }
        Ok(value)
    }

    fn bytes(&mut self, limit: usize) -> Result<Vec<u8>, String> {
        let len = self.len(limit)?;
        Ok(self.r.take(len)?.to_vec())
    }

    fn string_obj(&mut self, short: bool) -> Result<String, String> {
        let len = if short { usize::from(self.r.u8()?) } else { self.len(64 * 1024 * 1024)? };
        Ok(String::from_utf8_lossy(self.r.take(len)?).into_owned())
    }

    fn parse(&mut self) -> Result<Obj, String> {
        if self.depth > 200 { return Err("marshal nesting exceeds safety limit".to_owned()); }
        self.depth += 1;
        let raw_tag = self.r.u8()?;
        let flag_ref = raw_tag & 0x80 != 0;
        let tag = raw_tag & 0x7f;
        let value = match tag {
            b'0' => Obj::Other("NULL".to_owned()),
            b'N' => Obj::None,
            b'F' => Obj::Bool(false),
            b'T' => Obj::Bool(true),
            b'S' => Obj::Other("StopIteration".to_owned()),
            b'.' => Obj::Other("Ellipsis".to_owned()),
            b'i' => Obj::Int(i64::from(self.i32()?)),
            b'I' => Obj::Int(self.i64()?),
            b'g' => Obj::Float(f64::from_bits(self.r.le_u64()?)),
            b'f' => {
                let text = self.string_obj(true)?;
                Obj::Float(text.parse().unwrap_or(f64::NAN))
            }
            b'l' => {
                let n = self.i32()?;
                let count = usize::try_from(n.unsigned_abs()).map_err(|_| "marshal long too large".to_owned())?;
                if count > 1_000_000 { return Err("marshal long exceeds safety limit".to_owned()); }
                let mut hex = String::new();
                for _ in 0..count {
                    let digit = self.r.le_u16()?;
                    let _ = write!(hex, "{digit:04x}");
                }
                Obj::Other(if n < 0 { format!("-long(0x{hex})") } else { format!("long(0x{hex})") })
            }
            b's' => Obj::Bytes(self.bytes(128 * 1024 * 1024)?),
            b'u' | b't' | b'a' | b'A' => Obj::Str(self.string_obj(false)?),
            b'z' | b'Z' => Obj::Str(self.string_obj(true)?),
            b'(' => {
                let count = self.len(2_000_000)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count { items.push(self.parse()?); }
                Obj::Tuple(items)
            }
            b')' => {
                let count = usize::from(self.r.u8()?);
                let mut items = Vec::with_capacity(count);
                for _ in 0..count { items.push(self.parse()?); }
                Obj::Tuple(items)
            }
            b'[' => {
                let count = self.len(2_000_000)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count { items.push(self.parse()?); }
                Obj::List(items)
            }
            b'{' => {
                let mut items = Vec::new();
                for _ in 0..1_000_000 {
                    let key = self.parse()?;
                    if matches!(key, Obj::Other(ref s) if s == "NULL") { break; }
                    let value = self.parse()?;
                    items.push((key, value));
                }
                Obj::Dict(items)
            }
            b'<' | b'>' => {
                let count = self.len(2_000_000)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count { items.push(self.parse()?); }
                Obj::List(items)
            }
            b'r' => {
                let index = usize::try_from(self.r.le_u32()?).map_err(|_| "marshal ref overflow".to_owned())?;
                self.refs.get(index).cloned().ok_or_else(|| "invalid marshal reference".to_owned())?
            }
            b'c' => Obj::Code(self.parse_code()?),
            other => return Err(format!("unsupported marshal type 0x{other:02x}")),
        };
        self.depth -= 1;
        if flag_ref { self.refs.push(value.clone()); }
        Ok(value)
    }

    fn obj_bytes(&mut self) -> Result<Vec<u8>, String> {
        match self.parse()? {
            Obj::Bytes(v) => Ok(v),
            other => Err(format!("expected bytes in code object, got {other:?}")),
        }
    }

    fn obj_tuple(&mut self) -> Result<Vec<Obj>, String> {
        match self.parse()? {
            Obj::Tuple(v) | Obj::List(v) => Ok(v),
            other => Err(format!("expected tuple in code object, got {other:?}")),
        }
    }

    fn obj_string(&mut self) -> Result<String, String> {
        match self.parse()? {
            Obj::Str(v) => Ok(v),
            Obj::Bytes(v) => Ok(String::from_utf8_lossy(&v).into_owned()),
            other => Err(format!("expected string in code object, got {other:?}")),
        }
    }

    fn tuple_strings(items: Vec<Obj>) -> Vec<String> {
        items.into_iter().map(|o| match o {
            Obj::Str(s) => s,
            Obj::Bytes(v) => String::from_utf8_lossy(&v).into_owned(),
            other => format!("{other:?}"),
        }).collect()
    }

    fn parse_code(&mut self) -> Result<CodeObj, String> {
        let argcount = self.r.le_u32()?;
        let posonlyargcount = self.r.le_u32()?;
        let kwonlyargcount = self.r.le_u32()?;
        if self.modern_code {
            let stacksize = self.r.le_u32()?;
            let flags = self.r.le_u32()?;
            let code = self.obj_bytes()?;
            let consts = self.obj_tuple()?;
            let names = Self::tuple_strings(self.obj_tuple()?);
            let locals = Self::tuple_strings(self.obj_tuple()?);
            let _locals_kinds = self.parse()?;
            let filename = self.obj_string()?;
            let name = self.obj_string()?;
            let qualname = self.obj_string()?;
            let firstlineno = self.r.le_u32()?;
            let _linetable = self.parse()?;
            let _exceptiontable = self.parse()?;
            Ok(CodeObj { argcount, posonlyargcount, kwonlyargcount, stacksize, flags, code, consts, names, locals, filename, name, qualname, firstlineno })
        } else {
            let _nlocals = self.r.le_u32()?;
            let stacksize = self.r.le_u32()?;
            let flags = self.r.le_u32()?;
            let code = self.obj_bytes()?;
            let consts = self.obj_tuple()?;
            let names = Self::tuple_strings(self.obj_tuple()?);
            let locals = Self::tuple_strings(self.obj_tuple()?);
            let _freevars = self.parse()?;
            let _cellvars = self.parse()?;
            let filename = self.obj_string()?;
            let name = self.obj_string()?;
            let qualname = name.clone();
            let firstlineno = self.r.le_u32()?;
            let _lnotab = self.parse()?;
            Ok(CodeObj { argcount, posonlyargcount, kwonlyargcount, stacksize, flags, code, consts, names, locals, filename, name, qualname, firstlineno })
        }
    }
}

fn py_opcode(op: u8) -> &'static str {
    match op {
        0 => "CACHE", 1 => "POP_TOP", 2 => "PUSH_NULL", 9 => "NOP", 10 => "UNARY_POSITIVE",
        11 => "UNARY_NEGATIVE", 12 => "UNARY_NOT", 15 => "UNARY_INVERT", 25 => "BINARY_SUBSCR",
        30 => "GET_LEN", 35 => "PUSH_EXC_INFO", 36 => "CHECK_EXC_MATCH", 37 => "CHECK_EG_MATCH",
        49 => "WITH_EXCEPT_START", 50 => "GET_AITER", 51 => "GET_ANEXT", 52 => "BEFORE_ASYNC_WITH",
        53 => "BEFORE_WITH", 54 => "END_ASYNC_FOR", 60 => "STORE_SUBSCR", 61 => "DELETE_SUBSCR",
        68 => "GET_ITER", 69 => "GET_YIELD_FROM_ITER", 70 => "PRINT_EXPR", 71 => "LOAD_BUILD_CLASS",
        74 => "LOAD_ASSERTION_ERROR", 75 => "RETURN_GENERATOR", 82 => "LIST_TO_TUPLE", 83 => "RETURN_VALUE",
        84 => "IMPORT_STAR", 85 => "SETUP_ANNOTATIONS", 86 => "YIELD_VALUE", 87 => "ASYNC_GEN_WRAP",
        89 => "POP_EXCEPT", 90 => "STORE_NAME", 91 => "DELETE_NAME", 92 => "UNPACK_SEQUENCE",
        93 => "FOR_ITER", 94 => "UNPACK_EX", 95 => "STORE_ATTR", 96 => "DELETE_ATTR", 97 => "STORE_GLOBAL",
        98 => "DELETE_GLOBAL", 99 => "SWAP", 100 => "LOAD_CONST", 101 => "LOAD_NAME", 102 => "BUILD_TUPLE",
        103 => "BUILD_LIST", 104 => "BUILD_SET", 105 => "BUILD_MAP", 106 => "LOAD_ATTR", 107 => "COMPARE_OP",
        108 => "IMPORT_NAME", 109 => "IMPORT_FROM", 110 => "JUMP_FORWARD", 111 => "JUMP_IF_FALSE_OR_POP",
        112 => "JUMP_IF_TRUE_OR_POP", 114 => "POP_JUMP_FORWARD_IF_FALSE", 115 => "POP_JUMP_FORWARD_IF_TRUE",
        116 => "LOAD_GLOBAL", 117 => "IS_OP", 118 => "CONTAINS_OP", 119 => "RERAISE", 120 => "COPY",
        122 => "BINARY_OP", 123 => "SEND", 124 => "LOAD_FAST", 125 => "STORE_FAST", 126 => "DELETE_FAST",
        128 => "POP_JUMP_FORWARD_IF_NOT_NONE", 129 => "POP_JUMP_FORWARD_IF_NONE", 130 => "RAISE_VARARGS",
        132 => "MAKE_FUNCTION", 133 => "BUILD_SLICE", 134 => "JUMP_BACKWARD_NO_INTERRUPT", 135 => "MAKE_CELL",
        136 => "LOAD_CLOSURE", 137 => "LOAD_DEREF", 138 => "STORE_DEREF", 139 => "DELETE_DEREF",
        140 => "JUMP_BACKWARD", 142 => "CALL_FUNCTION_EX", 144 => "EXTENDED_ARG", 145 => "LIST_APPEND",
        146 => "SET_ADD", 147 => "MAP_ADD", 148 => "LOAD_CLASSDEREF", 149 => "COPY_FREE_VARS",
        151 => "RESUME", 152 => "MATCH_CLASS", 155 => "FORMAT_VALUE", 156 => "BUILD_CONST_KEY_MAP",
        157 => "BUILD_STRING", 160 => "LOAD_METHOD", 162 => "LIST_EXTEND", 163 => "SET_UPDATE",
        164 => "DICT_MERGE", 165 => "DICT_UPDATE", 166 => "PRECALL", 171 => "CALL",
        _ => "OP",
    }
}

fn obj_repr(obj: &Obj) -> String {
    match obj {
        Obj::None => "None".to_owned(),
        Obj::Bool(v) => v.to_string(),
        Obj::Int(v) => v.to_string(),
        Obj::Float(v) => v.to_string(),
        Obj::Bytes(v) => format!("b{:?}", String::from_utf8_lossy(v)),
        Obj::Str(v) => format!("{v:?}"),
        Obj::Tuple(v) => format!("({})", v.iter().map(obj_repr).collect::<Vec<_>>().join(", ")),
        Obj::List(v) => format!("[{}]", v.iter().map(obj_repr).collect::<Vec<_>>().join(", ")),
        Obj::Dict(v) => format!("{{{}}}", v.iter().map(|(k, val)| format!("{}: {}", obj_repr(k), obj_repr(val))).collect::<Vec<_>>().join(", ")),
        Obj::Code(c) => format!("<code {}>", c.qualname),
        Obj::Other(v) => v.clone(),
    }
}

fn render_code(code: &CodeObj, indent: &str, top_level: bool) -> String {
    let mut out = String::new();
    if top_level {
        let _ = writeln!(out, "# Decompiled by PolyDecomp built-in CPython engine");
        let _ = writeln!(out, "# file: {}  first line: {}", code.filename, code.firstlineno);
        let _ = writeln!(out, "# stacksize={} flags=0x{:x}\n", code.stacksize, code.flags);
    } else {
        let total = usize::try_from(code.argcount.saturating_add(code.kwonlyargcount)).unwrap_or(0);
        let params = code.locals.iter().take(total).cloned().collect::<Vec<_>>();
        let _ = writeln!(out, "{indent}def {}({}):", code.name, params.join(", "));
        let _ = writeln!(out, "{indent}    # qualname={} posonly={} kwonly={}", code.qualname, code.posonlyargcount, code.kwonlyargcount);
    }
    let body_indent = if top_level { indent.to_owned() } else { format!("{indent}    ") };
    if !code.consts.is_empty() {
        let _ = writeln!(out, "{body_indent}# constants:");
        for (i, value) in code.consts.iter().enumerate() {
            if !matches!(value, Obj::Code(_)) { let _ = writeln!(out, "{body_indent}#   const[{i}] = {}", obj_repr(value)); }
        }
    }
    if !code.names.is_empty() { let _ = writeln!(out, "{body_indent}# names: {}", code.names.join(", ")); }
    let _ = writeln!(out, "{body_indent}# bytecode (wordcode):");
    for (offset, pair) in code.code.chunks(2).enumerate() {
        let op = pair[0];
        let arg = pair.get(1).copied().unwrap_or(0);
        let name = py_opcode(op);
        let detail = match name {
            "LOAD_CONST" => code.consts.get(usize::from(arg)).map(obj_repr).unwrap_or_default(),
            "LOAD_NAME" | "STORE_NAME" | "LOAD_GLOBAL" | "LOAD_ATTR" | "STORE_ATTR" | "IMPORT_NAME" | "IMPORT_FROM" => {
                code.names.get(usize::from(arg)).cloned().unwrap_or_default()
            }
            "LOAD_FAST" | "STORE_FAST" | "DELETE_FAST" => code.locals.get(usize::from(arg)).cloned().unwrap_or_default(),
            _ => String::new(),
        };
        if name == "OP" {
            let _ = writeln!(out, "{body_indent}#   {:04x}: OP_{op:03} arg={arg} {detail}", offset * 2);
        } else {
            let _ = writeln!(out, "{body_indent}#   {:04x}: {name:<32} {arg:<3} {detail}", offset * 2);
        }
    }
    let nested = code.consts.iter().filter_map(|obj| match obj { Obj::Code(c) => Some(c), _ => None }).collect::<Vec<_>>();
    if !nested.is_empty() { out.push('\n'); }
    for child in nested { out.push_str(&render_code(child, indent, false)); out.push('\n'); }
    if !top_level && code.code.is_empty() { let _ = writeln!(out, "{body_indent}pass"); }
    out
}

fn pyc_header(data: &[u8]) -> Result<String, String> {
    if data.len() < 8 { return Err("pyc file is too short".to_owned()); }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    let flags = if data.len() >= 8 { u32::from_le_bytes([data[4], data[5], data[6], data[7]]) } else { 0 };
    Ok(format!("# pyc magic={magic} flags=0x{flags:08x}"))
}

fn try_parse(data: &[u8], offset: usize, modern: bool) -> Result<CodeObj, String> {
    let payload = data.get(offset..).ok_or_else(|| "pyc header exceeds file".to_owned())?;
    let mut reader = MarshalReader::new(payload, modern);
    match reader.parse()? {
        Obj::Code(code) => Ok(code),
        other => Err(format!("pyc root marshal object is not code: {other:?}")),
    }
}

pub fn decompile_pyc(data: &[u8]) -> Result<String, String> {
    let header = pyc_header(data)?;
    for (offset, modern) in [(16usize, true), (16, false), (12, false), (8, false)] {
        if let Ok(code) = try_parse(data, offset, modern) {
            return Ok(format!("{header}\n{}", render_code(&code, "", true)));
        }
    }
    let mut out = format!("{header}\n# PolyDecomp could not decode this marshal/code-object variant exactly.\n# Structural bytecode fallback follows.\n");
    let start = 16.min(data.len());
    for (i, pair) in data[start..].chunks(2).take(100_000).enumerate() {
        let op = pair[0];
        let arg = pair.get(1).copied().unwrap_or(0);
        let _ = writeln!(out, "# {:04x}: {:<28} {arg}", i * 2, py_opcode(op));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_opcodes() {
        assert_eq!(py_opcode(100), "LOAD_CONST");
        assert_eq!(py_opcode(83), "RETURN_VALUE");
    }

    #[test]
    fn pyc_header_short_rejected() {
        assert!(pyc_header(&[0, 1]).is_err());
    }
}
