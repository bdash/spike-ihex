use std::path::PathBuf;

use clap::Parser;
use spike_ihex::parse_hex_file;

#[derive(Parser, Debug)]
#[command(author, version, about = "Intel HEX parser with support for encrypted firmware", long_about = None)]
struct Args {
    /// Input HEX file to parse
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for decrypted firmware (optional)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let hex_content = std::fs::read_to_string(args.input)?;
    let mut context = parse_hex_file(&hex_content)?;

    if args.verbose {
        println!("Buffer size: {} bytes", context.buffer.len());
        if context.config_size > 0 {
            println!("Config words: {}", context.config_size);
            println!("Firmware start: 0x{:08X}", context.start_addr);
            println!("Firmware size: {} bytes", context.size);
        }
    }

    // Check if we have encrypted firmware
    if context.header.is_some() && context.config_size > 0 {
        println!("Detected encrypted firmware");

        if context.get_aes_key().is_some() {
            // Decrypt the firmware
            match context.decrypt_firmware() {
                Ok(decrypted_data) => {
                    println!("Successfully decrypted {} bytes", decrypted_data.len());

                    if args.verbose && decrypted_data.len() >= 8 {
                        // Show first two words (metadata)
                        let sp = u32::from_le_bytes([
                            decrypted_data[0],
                            decrypted_data[1],
                            decrypted_data[2],
                            decrypted_data[3],
                        ]);
                        let metadata = u32::from_le_bytes([
                            decrypted_data[4],
                            decrypted_data[5],
                            decrypted_data[6],
                            decrypted_data[7],
                        ]);
                        println!("Metadata: SP=0x{:08X}, Value=0x{:08X}", sp, metadata);
                    }

                    // Write output if specified
                    if let Some(output_path) = args.output {
                        std::fs::write(&output_path, &decrypted_data)?;
                        println!("Wrote decrypted firmware to {}", output_path.display());
                    }
                }
                Err(e) => {
                    eprintln!("Decryption failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    } else {
        // Standard unencrypted firmware
        println!("Standard Intel HEX format (no encryption)");

        if let Some(output_path) = args.output {
            // Write the buffer directly
            if !context.buffer.is_empty() {
                std::fs::write(&output_path, &context.buffer)?;
                println!(
                    "Wrote {} bytes to {}",
                    context.buffer.len(),
                    output_path.display()
                );
            }
        }
    }

    Ok(())
}
