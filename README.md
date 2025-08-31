# spike-ihex

A tool for parsing and decrypting the Intel HEX files used by Stern Spike
2 pinball machines for their node board firmware updates.

## Overview

This tool handles the proprietary encryption scheme used by Stern for updates
to the node boards within their Spike 2 games. This format extends the standard
Intel HEX format with custom record types related to AES-192-CBC encryption.

> [!NOTE]
> The .hex files that are found within Stern game code updates or SD card
> images only contain the second stage firmware. The bootloader is flashed onto
> the node boards at the factory and is not updated by software updates, and so
> is not present in the .hex files.

## Custom Intel HEX Extensions

The tool recognizes two vendor-specific record types:

- **Type 0x06 (Header)**: Contains a 16-byte scrambled header that serves as the AES initialization vector
- **Type 0x07 (Key)**: Contains extra data where the first 24 bytes (padded with 0xA5) form the AES-192 key

## Usage

```bash
spike-ihex --input <hex_file> [--output <output_file>] [--verbose]
```

### Options

- `-i, --input <FILE>`: Input Intel HEX file to parse (required)
- `-o, --output <FILE>`: Output file for decrypted firmware (optional)
- `-v, --verbose`: Enable verbose output showing metadata and decryption details
- `-h, --help`: Display help information
- `-V, --version`: Display version information

### Examples

Decrypt firmware and save to file:
```bash
spike-ihex --input node_firmware.hex --output decrypted.bin --verbose
```

Parse and analyze without saving:
```bash
spike-ihex --input node_firmware.hex --verbose
```

## Building

```bash
cargo build --release
```

## Known Issues

The `node4-*.hex` firmware files, containing firmware related to the Insider
Connected QR code scanner, are not yet handled correctly. Firmware for all
other node boards can be decrypted.

## License

See [LICENSE](LICENSE) file for details.
