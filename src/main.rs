use std::path::PathBuf;

use clap::CommandFactory;
use clap::Parser;
use colored::Colorize;

mod ncm;

#[derive(Parser)]
#[command(
    name = "ncmx",
    version = "0.1.0",
    about = "Convert Netease Cloud Music .ncm files to FLAC or MP3"
)]
struct Cli {
    /// Input .ncm file(s)
    files: Vec<PathBuf>,

    /// Process all files in a directory
    #[arg(short = 'd', long)]
    dir: Option<PathBuf>,

    /// Recursively process subdirectories (requires --dir)
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Output directory for converted files
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

fn process_file(path: &std::path::Path, output_dir: Option<&std::path::Path>) {
    // Skip non-.ncm files
    if !path
        .extension()
        .and_then(|e| e.to_str())
        .map_or(false, |e| e.eq_ignore_ascii_case("ncm"))
    {
        return;
    }

    let file_path_str = path.display();

    let mut ncm = match ncm::NcmFile::open(path) {
        Ok(ncm) => ncm,
        Err(e) => {
            eprintln!(
                "{} Reading '{}' failed: {}",
                "[Error]".red().bold(),
                file_path_str,
                e
            );
            return;
        }
    };

    if let Err(e) = ncm.dump(output_dir) {
        eprintln!(
            "{} Processing '{}' failed: {}",
            "[Error]".red().bold(),
            file_path_str,
            e
        );
        return;
    }

    let dump_path = ncm.dump_path().map(|p| p.display()).unwrap();

    if let Err(e) = ncm.fix_metadata(true) {
        eprintln!(
            "{} Fix metadata for '{}' failed: {}",
            "[Warning]".yellow().bold(),
            file_path_str,
            e
        );
    }

    println!(
        "{} '{}' -> '{}'",
        "[Done]".green().bold(),
        file_path_str,
        dump_path,
    );
}

fn main() {
    let cli = Cli::parse();

    // No args at all
    if std::env::args().len() == 1 {
        eprintln!(
            "{} No input files or directories specified.\n",
            "[Error]".red().bold()
        );
        let _ = Cli::command().print_help();
        eprintln!();
        std::process::exit(1);
    }

    // -r without -d is an error
    if cli.recursive && cli.dir.is_none() {
        eprintln!(
            "{} The -r option can only be used with the -d option",
            "[Error]".red().bold()
        );
        std::process::exit(1);
    }

    // Ensure output directory exists
    let output_dir = cli.output.as_ref();
    if let Some(dir) = output_dir {
        if dir.exists() {
            if !dir.is_dir() {
                eprintln!(
                    "{} Output directory '{}' is not valid.",
                    "[Error]".red().bold(),
                    dir.display()
                );
                std::process::exit(1);
            }
        } else {
            if let Err(e) = std::fs::create_dir_all(dir) {
                eprintln!(
                    "{} Failed to create output directory '{}': {}",
                    "[Error]".red().bold(),
                    dir.display(),
                    e
                );
                std::process::exit(1);
            }
        }
    }

    if let Some(source_dir) = &cli.dir {
        // Directory mode
        if !source_dir.is_dir() {
            eprintln!(
                "{} Source directory '{}' is not valid.",
                "[Error]".red().bold(),
                source_dir.display()
            );
            std::process::exit(1);
        }

        let output_for_dir = output_dir.map(|d| d.as_path());

        if cli.recursive {
            // Recursive: preserve directory structure under output
            for entry in walkdir::WalkDir::new(source_dir)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let relative = path.strip_prefix(source_dir).unwrap_or(path);

                let final_output = output_for_dir.map(|base| {
                    let parent = relative
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new(""));
                    let dir = base.join(parent);
                    let _ = std::fs::create_dir_all(&dir);
                    dir
                });

                process_file(path, final_output.as_deref());
            }
        } else {
            // Non-recursive: only top-level files
            if let Ok(entries) = std::fs::read_dir(source_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        process_file(&path, output_for_dir);
                    }
                }
            }
        }
    } else {
        // File args mode
        let output_for_files = output_dir.map(|d| d.as_path());
        for file_path in &cli.files {
            process_file(file_path, output_for_files);
        }
    }
}
