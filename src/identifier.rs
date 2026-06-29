//! Identifier newtypes used by SGP.22 messages.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{EuiccError, Result};
use crate::hex::{decode_hex, encode_hex_upper};

/// ICCID encoded as swapped BCD bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Iccid(Vec<u8>);

impl Iccid {
    /// Parses a text ICCID into swapped BCD bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::InvalidBcdIdentifier`] when `value` contains a
    /// non-hexadecimal character.
    ///
    /// # Examples
    ///
    /// ```
    /// let iccid = euicc::identifier::Iccid::new("8944478600004573128")?;
    /// assert_eq!(iccid.to_string(), "8944478600004573128");
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn new(value: &str) -> Result<Self> {
        Ok(Self(encode_swapped_bcd(value)?))
    }

    /// Builds an ICCID from already encoded swapped BCD bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the encoded ICCID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the ICCID and returns the encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Display for Iccid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&decode_swapped_bcd(&self.0))
    }
}

/// IMEI encoded as swapped BCD bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Imei(Vec<u8>);

impl Imei {
    /// Parses a text IMEI into swapped BCD bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::InvalidBcdIdentifier`] when `value` contains a
    /// non-hexadecimal character.
    pub fn new(value: &str) -> Result<Self> {
        Ok(Self(encode_swapped_bcd(value)?))
    }

    /// Builds an IMEI from already encoded swapped BCD bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns encoded IMEI bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the IMEI and returns encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Display for Imei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&decode_swapped_bcd(&self.0))
    }
}

/// ISD-P application identifier bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IsdpAid(Vec<u8>);

impl IsdpAid {
    /// Builds an ISD-P AID from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns raw ISD-P AID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for IsdpAid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex_upper(&self.0))
    }
}

/// Byte string serialized as uppercase hexadecimal JSON text.
///
/// # Errors
///
/// JSON deserialization returns [`EuiccError::Hex`] for invalid hexadecimal
/// text.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    /// Builds a hexadecimal byte string from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Parses hexadecimal text.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Hex`] when `text` has odd length or contains a
    /// non-hexadecimal digit.
    pub fn from_hex(text: &str) -> Result<Self> {
        Ok(Self(decode_hex(text)?))
    }

    /// Returns the wrapped bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for HexBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Serialize for HexBytes {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex_upper(&self.0))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(de::Error::custom)
    }
}

fn encode_swapped_bcd(value: &str) -> Result<Vec<u8>> {
    for byte in value.bytes() {
        if !byte.is_ascii_hexdigit() {
            return Err(EuiccError::InvalidBcdIdentifier);
        }
    }
    let mut text = value.to_owned();
    if !text.len().is_multiple_of(2) {
        text.push('F');
    }
    let mut bytes = decode_hex(&text).map_err(|_| EuiccError::InvalidBcdIdentifier)?;
    for byte in &mut bytes {
        *byte = (*byte >> 4) & 0x0F | (*byte << 4) & 0xF0;
    }
    Ok(bytes)
}

fn decode_swapped_bcd(value: &[u8]) -> String {
    let mut swapped = Vec::with_capacity(value.len());
    for byte in value {
        swapped.push((*byte >> 4) & 0x0F | (*byte << 4) & 0xF0);
    }
    let mut text = encode_hex_lower(&swapped);
    if let Some(index) = text.rfind('f') {
        text.truncate(index);
    }
    text
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iccid_round_trips_go_fixtures() {
        // Arrange
        let fixtures = [
            (
                vec![0x98, 0x44, 0x74, 0x68, 0x00, 0x00, 0x54, 0x37, 0x21, 0xF8],
                "8944478600004573128",
            ),
            (
                vec![0x98, 0x68, 0x10, 0x01, 0x9F, 0x09, 0x10, 0x06, 0x75, 0xF0],
                "89860110f9900160570",
            ),
        ];

        for (bytes, text) in fixtures {
            // Act
            let iccid = Iccid::from_bytes(bytes.clone());
            let parsed = Iccid::new(text).expect("fixture ICCID parses");

            // Assert
            assert_eq!(iccid.to_string(), text);
            assert_eq!(parsed.as_bytes(), bytes.as_slice());
        }
    }

    #[test]
    fn hex_bytes_json_matches_go_encoding() {
        // Arrange
        let hex = HexBytes::from_bytes([0x0A, 0xFF]);

        // Act
        let hex_json = serde_json::to_string(&hex).expect("hex serializes");

        // Assert
        assert_eq!(hex_json, "\"0AFF\"");
        assert_eq!(
            serde_json::from_str::<HexBytes>(&hex_json).expect("hex deserializes"),
            hex,
        );
    }
}
