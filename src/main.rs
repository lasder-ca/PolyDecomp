use clap::{Parser, Subcommand};
use polydecomp::{capabilities, decompile, default_output, detect, DecompileOptions};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "polydecomp", version, about = "Self-contained cross-platform multi-format decompiler")]
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
            println!("{}", serde_json::to_string_pretty(&detection).map_err(|error| error.to_string())?);
            Ok(())
        }
        Some(Commands::Doctor) => {
            println!("{}", serde_json::to_string_pretty(&capabilities()).map_err(|error| error.to_string())?);
            Ok(())
        }
        Some(Commands::Decompile { input, output, force }) => {
            let detection = detect(&input)?;
            let output = output.unwrap_or_else(|| default_output(&input, detection.kind));
            let result = decompile(&input, &output, &DecompileOptions { force }).map_err(|error| error.to_string())?;
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
