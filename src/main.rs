use clap::{Parser, Subcommand};
use polydecomp::{backend_names, decompile, default_output, detect, inventory, DecompileOptions};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "polydecomp", version, about = "Cross-platform multi-format decompiler")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Launch the native graphical interface.
    Gui,
    /// Identify a file and estimate the original language.
    Detect {
        input: PathBuf,
    },
    /// Show installed decompiler backends.
    Doctor,
    /// Decompile or disassemble a file.
    Decompile {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "auto")]
        backend: String,
        #[arg(long, default_value_t = 900)]
        timeout: u64,
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
                serde_json::to_string_pretty(&inventory()).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some(Commands::Decompile {
            input,
            output,
            backend,
            timeout,
            force,
        }) => {
            if !backend_names().contains(&backend.as_str()) {
                return Err(format!(
                    "unknown backend {backend:?}; valid values: {}",
                    backend_names().join(", ")
                ));
            }
            let detection = detect(&input)?;
            let output = output.unwrap_or_else(|| default_output(&input, detection.kind));
            let options = DecompileOptions {
                backend,
                timeout_secs: timeout,
                force,
            };
            let result = decompile(&input, &output, &options).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "input": result.input,
                    "output": result.output,
                    "backend": result.backend,
                    "kind": result.detection.kind,
                    "language": result.detection.language,
                    "description": result.detection.description,
                    "true_decompiler": result.true_decompiler,
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
