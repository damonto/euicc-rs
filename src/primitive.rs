//! BER primitive codecs used by SGP.22 TLV fields.

use crate::error::{EuiccError, Result};

/// Encodes a signed integer using the shortest two's-complement BER form.
#[must_use]
pub fn encode_i64(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0usize;
    while start < bytes.len() - 1 {
        let redundant_positive = bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0x00;
        let redundant_negative = bytes[start] == 0xFF && bytes[start + 1] & 0x80 == 0x80;
        if !redundant_positive && !redundant_negative {
            break;
        }
        start += 1;
    }
    bytes[start..].to_vec()
}

/// Decodes a signed integer from a BER two's-complement value.
///
/// # Errors
///
/// Returns [`EuiccError::IntegerTooLarge`] when `data.len() > max_bytes`.
pub fn decode_i64(data: &[u8], max_bytes: usize) -> Result<i64> {
    if data.is_empty() {
        return Ok(0);
    }
    if data.len() > max_bytes {
        return Err(EuiccError::IntegerTooLarge {
            max: max_bytes,
            got: data.len(),
        });
    }

    let sign = if data[0] & 0x80 == 0x80 { 0xFF } else { 0x00 };
    let mut bytes = [sign; 8];
    let start = bytes.len() - data.len();
    bytes[start..].copy_from_slice(data);
    Ok(i64::from_be_bytes(bytes))
}

/// Encodes a BER boolean.
#[must_use]
pub const fn encode_bool(value: bool) -> [u8; 1] {
    if value { [0xFF] } else { [0x00] }
}

/// Decodes a BER boolean.
#[must_use]
pub fn decode_bool(data: &[u8]) -> bool {
    data == [0xFF]
}

/// Encodes a BER bit string from most-significant-bit-first flags.
#[must_use]
pub fn encode_bit_string(bits: &[bool]) -> Vec<u8> {
    let padding_bits = (8 - bits.len() % 8) % 8;
    let mut data = vec![0; 1 + bits.len().div_ceil(8)];
    data[0] = padding_bits as u8;
    for (index, bit) in bits.iter().copied().enumerate() {
        if bit {
            let offset = 1 + index / 8;
            let bit_index = 7 - (index % 8);
            data[offset] |= 1 << bit_index;
        }
    }
    data
}

/// Decodes a BER bit string into most-significant-bit-first flags.
///
/// # Errors
///
/// Returns [`EuiccError::InvalidBitStringPadding`] when the payload has invalid
/// padding metadata or non-zero padding bits.
pub fn decode_bit_string(data: &[u8]) -> Result<Vec<bool>> {
    let Some((&padding, payload)) = data.split_first() else {
        return Err(EuiccError::InvalidBitStringPadding);
    };
    if padding > 7 || (payload.is_empty() && padding > 0) {
        return Err(EuiccError::InvalidBitStringPadding);
    }
    if let Some(last) = payload.last()
        && padding > 0
        && last & ((1 << padding) - 1) != 0
    {
        return Err(EuiccError::InvalidBitStringPadding);
    }

    let bit_len = payload.len() * 8 - usize::from(padding);
    let mut bits = Vec::with_capacity(bit_len);
    for index in 0..bit_len {
        let byte = payload[index / 8];
        let bit_index = 7 - (index % 8);
        bits.push(byte >> bit_index & 1 == 1);
    }
    Ok(bits)
}

/// Converts bit flags to a compact `0`/`1` string.
#[must_use]
pub fn bit_string_to_text(bits: &[bool]) -> String {
    let mut out = String::with_capacity(bits.len());
    for bit in bits {
        out.push(if *bit { '1' } else { '0' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_round_trips_go_fixtures() {
        // Arrange
        let fixtures = [
            (0, vec![0x00]),
            (127, vec![0x7F]),
            (128, vec![0x00, 0x80]),
            (256, vec![0x01, 0x00]),
            (-1, vec![0xFF]),
            (-128, vec![0x80]),
            (-129, vec![0xFF, 0x7F]),
            (-1000, vec![0xFC, 0x18]),
        ];

        for (value, encoded) in fixtures {
            // Act
            let actual = encode_i64(value);
            let decoded = decode_i64(&encoded, 8).expect("fixture integer decodes");

            // Assert
            assert_eq!(actual, encoded);
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn bit_string_round_trips_go_fixture() {
        // Arrange
        let encoded = [0x06, 0x6E, 0x5D, 0xC0];

        // Act
        let bits = decode_bit_string(&encoded).expect("fixture bit string decodes");
        let actual = encode_bit_string(&bits);

        // Assert
        assert_eq!(bit_string_to_text(&bits), "011011100101110111");
        assert_eq!(actual, encoded);
    }

    #[test]
    fn bit_string_rejects_invalid_padding() {
        // Arrange
        let encoded = [0x08, 0x6E, 0x5D, 0xC0];

        // Act
        let err = decode_bit_string(&encoded);

        // Assert
        assert!(matches!(err, Err(EuiccError::InvalidBitStringPadding)));
    }
}
