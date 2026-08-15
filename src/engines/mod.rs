pub mod dex;
pub mod dotnet;
pub mod jvm;
pub mod lua;
pub mod native;
pub mod pyc;
pub mod wasm;

use std::fmt::Write as _;

pub const MAX_INPUT_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_ARCHIVE_MEMBER: u64 = 128 * 1024 * 1024;
pub const MAX_ARCHIVE_TOTAL: u64 = 512 * 1024 * 1024;
pub const MAX_ARCHIVE_ENTRIES: usize = 20_000;

#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub const fn position(&self) -> usize {
        self.pos
    }

    pub fn seek(&mut self, pos: usize) -> Result<(), String> {
        if pos > self.data.len() {
            return Err("offset outside input".to_owned());
        }
        self.pos = pos;
        Ok(())
    }

    pub fn skip(&mut self, len: usize) -> Result<(), String> {
        let next = self
            .pos
            .checked_add(len)
            .ok_or_else(|| "offset overflow".to_owned())?;
        self.seek(next)
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| "length overflow".to_owned())?;
        if end > self.data.len() {
            return Err("truncated input".to_owned());
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub fn be_u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn be_u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn le_u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn le_u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn le_u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

pub fn checked_slice(data: &[u8], offset: usize, len: usize) -> Result<&[u8], String> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| "range overflow".to_owned())?;
    data.get(offset..end)
        .ok_or_else(|| "range outside input".to_owned())
}

pub fn read_uleb(data: &[u8], pos: &mut usize) -> Result<u32, String> {
    let mut value = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| "truncated ULEB128".to_owned())?;
        *pos += 1;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err("ULEB128 value is too large".to_owned())
}

pub fn printable_strings(data: &[u8], min_len: usize, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (index, byte) in data.iter().copied().enumerate() {
        let printable = matches!(byte, 0x20..=0x7e) || byte >= 0xc2;
        if printable {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take()
            && index.saturating_sub(begin) >= min_len
            && let Ok(text) = std::str::from_utf8(&data[begin..index])
        {
            out.push(text.to_owned());
            if out.len() >= max {
                return out;
            }
        }
    }
    if let Some(begin) = start
        && data.len().saturating_sub(begin) >= min_len
        && let Ok(text) = std::str::from_utf8(&data[begin..])
    {
        out.push(text.to_owned());
    }
    out.truncate(max);
    out
}

pub fn hexdump(data: &[u8], base: u64, max_bytes: usize) -> String {
    let mut out = String::new();
    let shown = &data[..data.len().min(max_bytes)];
    for (row, chunk) in shown.chunks(16).enumerate() {
        let address = base.saturating_add((row * 16) as u64);
        let _ = write!(out, "{address:08x}  ");
        for i in 0..16 {
            if let Some(byte) = chunk.get(i) {
                let _ = write!(out, "{byte:02x} ");
            } else {
                out.push_str("   ");
            }
        }
        out.push(' ');
        for byte in chunk {
            let c = if matches!(*byte, 0x20..=0x7e) {
                *byte as char
            } else {
                '.'
            };
            out.push(c);
        }
        out.push('\n');
    }
    if data.len() > max_bytes {
        let _ = writeln!(out, "... {} bytes omitted ...", data.len() - max_bytes);
    }
    out
}
