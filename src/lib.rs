#![forbid(unsafe_code)]

pub mod decompile;
pub mod detect;
pub mod gui;
pub mod i18n;
pub mod model;
pub mod tools;

pub use decompile::{backend_names, decompile, default_output, DecompileError};
pub use detect::detect;
pub use model::{DecompileOptions, DecompileResult, Detection, FileKind, Tool};
pub use tools::inventory;
