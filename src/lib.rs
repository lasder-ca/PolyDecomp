#![forbid(unsafe_code)]

pub mod capabilities;
pub mod decompile;
pub mod detect;
mod engines;
pub mod gui;
pub mod i18n;
pub mod model;

pub use capabilities::capabilities;
pub use decompile::{DecompileError, decompile, default_output};
pub use detect::detect;
pub use model::{Capability, DecompileOptions, DecompileResult, Detection, FileKind};
