use super::ImportRecord;

#[derive(Debug, Clone)]
struct PeSection {
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
}

#[derive(Debug, Clone)]
struct PeLayout {
    image_base: u64,
    pointer_size: usize,
    size_of_headers: u32,
    import_rva: u32,
    sections: Vec<PeSection>,
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
    ]))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn parse_layout(data: &[u8]) -> Option<PeLayout> {
    if data.get(..2)? != b"MZ" {
        return None;
    }
    let pe_offset = usize::try_from(read_u32(data, 0x3c)?).ok()?;
    if data.get(pe_offset..pe_offset.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }

    let section_count = usize::from(read_u16(data, pe_offset.checked_add(6)?)?);
    let optional_size = usize::from(read_u16(data, pe_offset.checked_add(20)?)?);
    let optional = pe_offset.checked_add(24)?;
    let magic = read_u16(data, optional)?;

    let (image_base, pointer_size, data_directory_offset, number_of_rva_offset) = match magic {
        0x20b => (
            read_u64(data, optional.checked_add(24)?)?,
            8usize,
            112usize,
            108usize,
        ),
        0x10b => (
            u64::from(read_u32(data, optional.checked_add(28)?)?),
            4usize,
            96usize,
            92usize,
        ),
        _ => return None,
    };

    let number_of_rva = read_u32(data, optional.checked_add(number_of_rva_offset)?)?;
    if number_of_rva <= 1 {
        return None;
    }
    let import_directory = optional
        .checked_add(data_directory_offset)?
        .checked_add(8)?;
    let import_rva = read_u32(data, import_directory)?;
    let size_of_headers = read_u32(data, optional.checked_add(60)?)?;

    let section_table = optional.checked_add(optional_size)?;
    let mut sections = Vec::with_capacity(section_count.min(256));
    for index in 0..section_count.min(256) {
        let offset = section_table.checked_add(index.checked_mul(40)?)?;
        sections.push(PeSection {
            virtual_size: read_u32(data, offset.checked_add(8)?)?,
            virtual_address: read_u32(data, offset.checked_add(12)?)?,
            raw_size: read_u32(data, offset.checked_add(16)?)?,
            raw_pointer: read_u32(data, offset.checked_add(20)?)?,
        });
    }

    Some(PeLayout {
        image_base,
        pointer_size,
        size_of_headers,
        import_rva,
        sections,
    })
}

fn rva_to_offset(layout: &PeLayout, data_len: usize, rva: u32) -> Option<usize> {
    if rva < layout.size_of_headers {
        let offset = usize::try_from(rva).ok()?;
        return (offset < data_len).then_some(offset);
    }

    for section in &layout.sections {
        let span = section.virtual_size.max(section.raw_size);
        let end = section.virtual_address.checked_add(span)?;
        if rva < section.virtual_address || rva >= end {
            continue;
        }
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= section.raw_size {
            return None;
        }
        let raw = section.raw_pointer.checked_add(delta)?;
        let offset = usize::try_from(raw).ok()?;
        return (offset < data_len).then_some(offset);
    }
    None
}

fn read_c_string(data: &[u8], offset: usize, max_len: usize) -> Option<String> {
    let end_limit = offset.checked_add(max_len)?.min(data.len());
    let bytes = data.get(offset..end_limit)?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let value = std::str::from_utf8(&bytes[..end]).ok()?.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn normalize_dll(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(".dll")
        .trim_end_matches(".DLL")
        .to_owned()
}

pub(super) fn imports(data: &[u8]) -> Vec<ImportRecord> {
    let Some(layout) = parse_layout(data) else {
        return Vec::new();
    };
    if layout.import_rva == 0 {
        return Vec::new();
    }
    let Some(mut descriptor) = rva_to_offset(&layout, data.len(), layout.import_rva) else {
        return Vec::new();
    };

    let mut output = Vec::new();
    for _ in 0..4096 {
        let Some(original_first_thunk) = read_u32(data, descriptor) else {
            break;
        };
        let Some(name_rva) = read_u32(data, descriptor.saturating_add(12)) else {
            break;
        };
        let Some(first_thunk) = read_u32(data, descriptor.saturating_add(16)) else {
            break;
        };
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll = rva_to_offset(&layout, data.len(), name_rva)
            .and_then(|offset| read_c_string(data, offset, 1024))
            .map_or_else(|| "unknown".to_owned(), |value| normalize_dll(&value));
        let lookup_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        for index in 0..65_536usize {
            let Some(delta) = index.checked_mul(layout.pointer_size) else {
                break;
            };
            let Ok(delta_rva) = u32::try_from(delta) else {
                break;
            };
            let Some(entry_rva) = lookup_rva.checked_add(delta_rva) else {
                break;
            };
            let Some(entry_offset) = rva_to_offset(&layout, data.len(), entry_rva) else {
                break;
            };
            let thunk = if layout.pointer_size == 8 {
                read_u64(data, entry_offset)
            } else {
                read_u32(data, entry_offset).map(u64::from)
            };
            let Some(thunk) = thunk else {
                break;
            };
            if thunk == 0 {
                break;
            }

            let ordinal_mask = if layout.pointer_size == 8 {
                1u64 << 63
            } else {
                1u64 << 31
            };
            let name = if thunk & ordinal_mask != 0 {
                format!("ordinal_{}", thunk & 0xffff)
            } else {
                let name_rva = u32::try_from(thunk & 0x7fff_ffff).ok();
                name_rva
                    .and_then(|rva| rva_to_offset(&layout, data.len(), rva))
                    .and_then(|offset| read_c_string(data, offset.saturating_add(2), 4096))
                    .unwrap_or_else(|| format!("import_{index}"))
            };

            let iat_rva = first_thunk.checked_add(delta_rva);
            let Some(iat_rva) = iat_rva else {
                break;
            };
            output.push(ImportRecord {
                dll: dll.clone(),
                name,
                iat_address: layout.image_base.saturating_add(u64::from(iat_rva)),
            });
            if output.len() >= 65_536 {
                break;
            }
        }

        descriptor = match descriptor.checked_add(20) {
            Some(next) if next <= data.len() => next,
            _ => break,
        };
        if output.len() >= 65_536 {
            break;
        }
    }

    output.sort_by_key(|entry| entry.iat_address);
    output.dedup_by_key(|entry| entry.iat_address);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        assert!(imports(b"not a PE file").is_empty());
    }

    #[test]
    fn normalizes_dll_suffix() {
        assert_eq!(normalize_dll("KERNEL32.dll"), "KERNEL32");
        assert_eq!(normalize_dll("USER32.DLL"), "USER32");
    }
}
