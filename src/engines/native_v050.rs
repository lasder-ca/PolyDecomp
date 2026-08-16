use crate::model::NativeOutputFormat;
use serde::{Deserialize, Serialize};

mod lift;
mod pe;
mod render;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RawInstruction {
    pub address: u64,
    pub assembly: String,
    pub pseudocode: String,
    pub control: String,
    pub target: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RawBlock {
    pub address: u64,
    pub successors: Vec<u64>,
    pub instructions: Vec<RawInstruction>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RawFunction {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub origin: String,
    pub blocks: Vec<RawBlock>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RawReport {
    pub format: String,
    pub architecture: String,
    pub entry: u64,
    pub sections: Vec<SectionInfo>,
    pub recovered_strings: Vec<String>,
    pub functions: Vec<RawFunction>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ImportRecord {
    pub dll: String,
    pub name: String,
    pub iat_address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ArgumentInfo {
    pub name: String,
    pub register: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct EnhancedInstruction {
    pub address: u64,
    pub assembly: String,
    pub pseudocode: String,
    pub raw_pseudocode: String,
    pub control: String,
    pub target: Option<u64>,
    pub symbol: Option<String>,
    pub memory_reference: Option<String>,
    pub confidence: String,
    pub hidden_in_readable_output: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct EnhancedBlock {
    pub address: u64,
    pub role: String,
    pub successors: Vec<u64>,
    pub instructions: Vec<EnhancedInstruction>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct EnhancedFunction {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub origin: String,
    pub abi: String,
    pub arguments: Vec<ArgumentInfo>,
    pub stack_locals: Vec<String>,
    pub calls: Vec<String>,
    pub loop_headers: Vec<u64>,
    pub returns_value: bool,
    pub blocks: Vec<EnhancedBlock>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct EnhancedReport {
    pub engine: String,
    pub format: String,
    pub architecture: String,
    pub entry: u64,
    pub sections: Vec<SectionInfo>,
    pub recovered_strings: Vec<String>,
    pub imports: Vec<ImportRecord>,
    pub functions: Vec<EnhancedFunction>,
    pub notes: Vec<String>,
}

pub fn decompile_native(data: &[u8], output_format: NativeOutputFormat) -> Result<String, String> {
    let raw_json = super::native_legacy::decompile_native(data, NativeOutputFormat::Json)?;
    let raw: RawReport = serde_json::from_str(&raw_json)
        .map_err(|error| format!("native IR parse error: {error}"))?;
    let report = lift::enhance(data, raw)?;

    if output_format == NativeOutputFormat::Json {
        return serde_json::to_string_pretty(&report).map_err(|error| error.to_string());
    }
    Ok(render::render(&report, output_format))
}
