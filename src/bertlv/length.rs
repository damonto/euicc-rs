use crate::error::{EuiccError, Result};

use super::MAX_LENGTH;

/// Encodes a BER length using short or definite long form.
///
/// # Errors
///
/// Returns [`EuiccError::LengthTooLarge`] when `length > 0xFF_FF_FF`.
pub fn encode_length(length: usize) -> Result<Vec<u8>> {
    match length {
        0..=0x7F => Ok(vec![length as u8]),
        0x80..=0xFF => Ok(vec![0x81, length as u8]),
        0x100..=0xFFFF => Ok(vec![0x82, (length >> 8) as u8, length as u8]),
        0x1_0000..=MAX_LENGTH => Ok(vec![
            0x83,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ]),
        _ => Err(EuiccError::LengthTooLarge {
            max: MAX_LENGTH,
            got: length,
        }),
    }
}

/// Decodes a BER length from the front of `data`.
///
/// # Errors
///
/// Returns [`EuiccError::LengthEncoding`] for unsupported indefinite or
/// truncated encodings.
pub fn decode_length(data: &[u8]) -> Result<(usize, usize)> {
    let Some(&first) = data.first() else {
        return Err(EuiccError::LengthEncoding(
            "expected one length byte".to_owned(),
        ));
    };
    match first {
        0x00..=0x7F => Ok((usize::from(first), 1)),
        0x81 => {
            let value = *data
                .get(1)
                .ok_or_else(|| EuiccError::LengthEncoding("expected one long byte".to_owned()))?;
            if value < 0x80 {
                return Err(EuiccError::LengthEncoding(
                    "non-minimal long-form length".to_owned(),
                ));
            }
            Ok((usize::from(value), 2))
        }
        0x82 => {
            let bytes = data
                .get(1..3)
                .ok_or_else(|| EuiccError::LengthEncoding("expected two long bytes".to_owned()))?;
            let value = (usize::from(bytes[0]) << 8) | usize::from(bytes[1]);
            if value < 0x100 {
                return Err(EuiccError::LengthEncoding(
                    "non-minimal long-form length".to_owned(),
                ));
            }
            Ok((value, 3))
        }
        0x83 => {
            let bytes = data.get(1..4).ok_or_else(|| {
                EuiccError::LengthEncoding("expected three long bytes".to_owned())
            })?;
            let value = (usize::from(bytes[0]) << 16)
                | (usize::from(bytes[1]) << 8)
                | usize::from(bytes[2]);
            if value < 0x1_0000 {
                return Err(EuiccError::LengthEncoding(
                    "non-minimal long-form length".to_owned(),
                ));
            }
            Ok((value, 4))
        }
        _ => Err(EuiccError::LengthEncoding(
            "unsupported length encoding".to_owned(),
        )),
    }
}
