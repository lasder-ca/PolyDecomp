use clap::{Parser, Subcommand, ValueEnum};
use polydecomp::{
    DecompileOptions, NativeOutputFormat, capabilities, decompile, default_output_with_format,
    detect,
};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliNativeFormat {
    C,
    Rust,
    Python,
    Asm,
    Json,
}

impl From<CliNativeFormat> for NativeOutputFormat {
    fn from(value: CliNativeFormat) -> Self {
        match value {
            CliNativeFormat::C => Self::C,
            CliNativeFormat::Rust => Self::Rust,
            CliNativeFormat::Python => Self::Python,
            CliNativeFormat::Asm => Self::Assembly,
            CliNativeFormat::Json => Self::Json,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "polydecomp",
    version,
    about = "Self-contained cross-platform multi-format decompiler"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Launch the native graphical interface.
    Gui,
    /// Identify a file and estimate the original language.
    Detect { input: PathBuf },
    /// Show built-in decompilation capabilities.
    Doctor,
    /// Decompile, disassemble, or structurally analyze a file using only the built-in engine.
    Decompile {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Native-binary output format. Other input formats keep their natural source format.
        #[arg(long, value_enum, default_value = "c")]
        format: CliNativeFormat,
        #[arg(long)]
        force: bool,
    },
}

fn run_cli() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        None | Some(Commands::Gui) => polydecomp::gui::run().map_err(|error| error.to_string()),
        Some(Commands::Detect { input }) => {
            let detection = detect(&input)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&detection).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some(Commands::Doctor) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&capabilities()).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some(Commands::Decompile {
            input,
            output,
            format,
            force,
        }) => {
            let detection = detect(&input)?;
            let native_format = NativeOutputFormat::from(format);
            let output = output
                .unwrap_or_else(|| default_output_with_format(&input, detection.kind, native_format));
            let result = decompile(
                &input,
                &output,
                &DecompileOptions {
                    force,
                    native_format,
                },
            )
            .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "input": result.input,
                    "output": result.output,
                    "engine": result.engine,
                    "kind": result.detection.kind,
                    "language": result.detection.language,
                    "description": result.detection.description,
                    "fidelity": result.fidelity,
                    "native_output_format": native_format.as_str(),
                    "external_backends": false,
                }))
                .map_err(|error| error.to_string())?
            );
            Ok(())
        }
    }
}

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("polydecomp: error: {error}");
        std::process::exit(2);
    }
}
