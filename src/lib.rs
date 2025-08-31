use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use thiserror::Error;

type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    Data = 0x00,
    EndOfFile = 0x01,
    ExtendedSegmentAddress = 0x02,
    StartSegmentAddress = 0x03,
    ExtendedLinearAddress = 0x04,
    StartLinearAddress = 0x05,

    // Stern-specific record types
    Header = 0x06, // Contains IV and metadata
    Key = 0x07,
}

impl RecordType {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for RecordType {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(RecordType::Data),
            0x01 => Ok(RecordType::EndOfFile),
            0x02 => Ok(RecordType::ExtendedSegmentAddress),
            0x03 => Ok(RecordType::StartSegmentAddress),
            0x04 => Ok(RecordType::ExtendedLinearAddress),
            0x05 => Ok(RecordType::StartLinearAddress),
            0x06 => Ok(RecordType::Header),
            0x07 => Ok(RecordType::Key),
            _ => Err(ParseError::InvalidRecordType(value)),
        }
    }
}

impl TryFrom<&str> for RecordType {
    type Error = ParseError;

    fn try_from(hex_str: &str) -> Result<Self, Self::Error> {
        let value = u8::from_str_radix(hex_str, 16)?;
        RecordType::try_from(value)
    }
}

#[derive(Debug)]
pub struct Record {
    pub length: u8,
    pub address: u16,
    pub record_type: RecordType,
    pub data: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Line does not start with ':'")]
    InvalidStartCode,

    #[error("Invalid length field")]
    InvalidLength,

    #[error("Invalid hex digit")]
    InvalidHexDigit(#[from] std::num::ParseIntError),

    #[error("Invalid record type: 0x{0:02x}")]
    InvalidRecordType(u8),

    #[error("Checksum mismatch: expected 0x{expected:02x}, got 0x{actual:02x}")]
    ChecksumMismatch { expected: u8, actual: u8 },

    #[error("Unexpected end of line")]
    UnexpectedEndOfLine,

    #[error("Invalid record format: {0}")]
    InvalidRecordFormat(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),
}

/// Parse a line of Intel HEX format
pub fn parse_record(line: &str) -> Result<Record, ParseError> {
    let line = line.trim();

    if !line.starts_with(':') {
        return Err(ParseError::InvalidStartCode);
    }

    // Minimum length: : + 2(len) + 4(addr) + 2(type) + 2(checksum) = 11
    if line.len() < 11 {
        return Err(ParseError::UnexpectedEndOfLine);
    }

    if line.len() < 3 {
        return Err(ParseError::UnexpectedEndOfLine);
    }

    let length = u8::from_str_radix(&line[1..3], 16)?;
    let expected_len = 11 + (length as usize * 2);
    if line.len() != expected_len {
        return Err(ParseError::InvalidLength);
    }

    let address_field = &line[3..7];
    let record_type_field = &line[7..9];
    let data_field = &line[9..9 + (length as usize * 2)];
    let checksum_field = &line[9 + (length as usize * 2)..];

    let address = u16::from_str_radix(address_field, 16)?;
    let record_type = RecordType::try_from(record_type_field)?;

    let data = data_field
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let hex_str = std::str::from_utf8(chunk).map_err(|_| ParseError::InvalidLength)?;
            Ok(u8::from_str_radix(hex_str, 16)?)
        })
        .collect::<Result<Vec<_>, ParseError>>()?;

    let expected_checksum = u8::from_str_radix(checksum_field, 16)?;

    let sum: u32 = length as u32
        + (address >> 8) as u32  // addr_high
        + (address & 0xff) as u32 // addr_low
        + record_type.as_u8() as u32
        + data.iter().map(|&b| b as u32).sum::<u32>();
    let actual_checksum = (256 - (sum & 0xff)) as u8;

    if actual_checksum != expected_checksum {
        return Err(ParseError::ChecksumMismatch {
            expected: actual_checksum,
            actual: expected_checksum,
        });
    }

    Ok(Record {
        length,
        address,
        record_type,
        data,
    })
}

/// Scramble 16-byte header using XOR transformation
pub fn scramble_header(data: &mut [u8; 16]) {
    let original = *data;

    // TODO: It's not clear what exactly this is doing.
    // This is just a direct translation of the ARMv7 machine code.

    let mut r3 = original[6];
    let mut r4 = original[2];
    let r5 = original[8];
    let r10 = original[3];
    let r9 = original[7];
    let mut re = original[5];
    let mut r1 = original[9];
    let r6_orig = original[0xa];
    let r3_orig = original[0xc];
    let r8 = original[0xb];
    let r11 = original[4];
    let r5_orig = original[0];
    let mut r12 = original[0xf];
    let mut r2 = original[0xd];
    let r4_orig = original[1];

    r4 ^= r3; // eor r4, r4, r3
    let r12_temp = r9 ^ r10; // eor r12, r9, r10
    let r2_temp = r1 ^ re; // eor r2, r1, lr
    re ^= r5; // eor lr, lr, r5
    r1 ^= r6_orig; // eor r1, r1, r6
    let r5_new = r5_orig ^ r11; // eor r5, r5, r11
    let r6 = r2_temp ^ r3_orig; // eor r6, r2, r3
    let r7 = r8 ^ r12_temp; // eor r7, r8, r12
    r3 = r10 ^ r4; // eor r3, r10, r4
    re ^= r9; // eor lr, lr, r9
    r12 ^= r7; // eor r12, r12, r7
    r1 ^= r8; // eor r1, r1, r8
    r2 ^= r6; // eor r2, r2, r6
    let r3_new = r5_new ^ r4_orig; // eor r3, r5, r4

    data[6] = r3;
    data[8] = re;
    data[0xf] = r12;
    data[0xa] = r1;
    data[0xc] = r2;
    data[4] = r3_new;
}

pub struct FirmwareContext {
    pub header: Option<[u8; 16]>,
    pub buffer: Vec<u8>,
    pub base_address: u32,
    pub start_addr: u32,
    pub size: u32,
    pub config_size: u16,
}

impl FirmwareContext {
    pub fn new() -> Self {
        Self {
            header: None,
            buffer: Vec::new(),
            base_address: 0,
            start_addr: u32::MAX,
            size: 0,
            config_size: 0,
        }
    }

    pub fn process_record(&mut self, record: Record) -> Result<(), ParseError> {
        match record.record_type {
            RecordType::Data => {
                let addr = (self.base_address + record.address as u32) as usize;
                let end = addr + record.data.len();

                if end > self.buffer.len() {
                    // Grow by rounding up to the next 1KB boundary, padding with 0xff
                    let new_size = (end + 0x3ff) & !0x3ff;
                    self.buffer.resize(new_size, 0xff);
                }

                self.buffer[addr..addr + record.data.len()].copy_from_slice(&record.data);

                // Update start_addr and size
                self.start_addr = self.start_addr.min(addr as u32);
                let end_addr = self.start_addr + self.size;
                self.size = end_addr.max(end as u32) - self.start_addr;
            }

            RecordType::ExtendedLinearAddress => {
                if record.data.len() != 2 {
                    return Err(ParseError::InvalidRecordFormat(
                        "Extended linear address must have 2 bytes".to_string(),
                    ));
                }
                self.base_address =
                    ((record.data[0] as u32) << 24) | ((record.data[1] as u32) << 16);
            }

            RecordType::Header => {
                if record.address != 0 || record.data.len() != 16 {
                    return Err(ParseError::InvalidRecordFormat(
                        "Type 0x06 must be at address 0 with 16 bytes".to_string(),
                    ));
                }

                let mut header = [0u8; 16];
                header.copy_from_slice(&record.data);

                let mut metadata = header;
                scramble_header(&mut metadata);

                let size = (metadata[0x0a] as u16) | ((metadata[0x0c] as u16) << 8);
                self.config_size = size;
                self.buffer = vec![0xff; (size as usize) * 2];
                self.header = Some(header);
            }

            RecordType::Key => {
                if self.buffer.is_empty() {
                    return Err(ParseError::InvalidRecordFormat(
                        "Type 0x07 before type 0x06".to_string(),
                    ));
                }

                let addr = record.address as usize;
                if addr >= self.config_size as usize {
                    return Err(ParseError::InvalidRecordFormat(
                        "Config address exceeds size".to_string(),
                    ));
                }

                let mut offset = addr * 2;
                for chunk in record.data.chunks(2) {
                    if offset + 1 < self.buffer.len() {
                        self.buffer[offset] = chunk[0];
                        self.buffer[offset + 1] = chunk[1];
                        offset += 2;
                    }
                }
            }

            RecordType::EndOfFile => {}

            _ => {
                // Other record types are not used
            }
        }

        Ok(())
    }

    /// Get the AES-192 key from config data
    pub fn get_aes_key(&self) -> Option<[u8; 24]> {
        if self.buffer.is_empty() || self.config_size == 0 {
            return None;
        }

        let mut key_buffer = [0xa5u8; 24];

        // Copy up to 24 bytes from config data
        let config_bytes = (self.config_size as usize) * 2;
        let copy_len = config_bytes.min(24);
        if copy_len > 0 && copy_len <= self.buffer.len() {
            key_buffer[..copy_len].copy_from_slice(&self.buffer[..copy_len]);
        }

        Some(key_buffer)
    }

    /// The scrambled header is used as the IV
    pub fn get_iv(&self) -> Option<&[u8; 16]> {
        self.header.as_ref()
    }

    /// Decrypt the firmware data using AES-192-CBC
    pub fn decrypt_firmware(&mut self) -> Result<Vec<u8>, ParseError> {
        let key = self
            .get_aes_key()
            .ok_or_else(|| ParseError::DecryptionError("No AES key available".to_string()))?;
        let iv = self
            .get_iv()
            .ok_or_else(|| ParseError::DecryptionError("No IV available".to_string()))?;

        if self.start_addr == u32::MAX || self.size == 0 {
            return Err(ParseError::DecryptionError(
                "No firmware data to process".to_string(),
            ));
        }

        let start = self.start_addr as usize;
        let size = self.size as usize;

        if start + size > self.buffer.len() {
            return Err(ParseError::DecryptionError(
                "Invalid firmware range".to_string(),
            ));
        }

        let mut firmware_data = self.buffer[start..start + size].to_vec();

        // Pad to AES block size
        let padding_needed = (16 - (firmware_data.len() % 16)) % 16;
        if padding_needed > 0 {
            firmware_data.extend(vec![0; padding_needed]);
        }

        // Decrypt using AES-192-CBC
        let cipher = Aes192CbcDec::new(&key.into(), iv.into());
        cipher
            .decrypt_padded_mut::<NoPadding>(&mut firmware_data)
            .map_err(|_| ParseError::DecryptionError("AES decryption failed".to_string()))?;

        // Return original size
        firmware_data.truncate(size);
        Ok(firmware_data)
    }
}

impl Default for FirmwareContext {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_hex_file(content: &str) -> Result<FirmwareContext, ParseError> {
    let mut context = FirmwareContext::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match parse_record(line) {
            Ok(record) => {
                context.process_record(record)?;
            }
            Err(e) => {
                eprintln!("Error on line {}: {:?}", line_num + 1, e);
                return Err(e);
            }
        }
    }

    Ok(context)
}
