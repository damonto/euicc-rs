//! Hexadecimal text encoding used by protocol JSON and diagnostics.

use crate::error::{EuiccError, Result};

/// Encodes bytes as uppercase hexadecimal.
#[must_use]
pub fn encode_hex_upper(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Decodes hexadecimal text.
///
/// # Errors
///
/// Returns [`EuiccError::Hex`] when the text length is odd or a digit is
/// outside `[0-9A-Fa-f]`.
pub fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(EuiccError::Hex("odd-length text".to_owned()));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push(high << 4 | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(EuiccError::Hex(format!("invalid digit 0x{other:02X}"))),
    }
}
