use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{EuiccError, Result};

/// BER OCTET STRING bytes serialized as base64 JSON text.
///
/// Deserialization accepts padded and unpadded standard base64, matching the
/// JSON encoding used by SGP.22 HTTP messages for binary BER values.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct OctetString(Vec<u8>);

impl OctetString {
    /// Builds an octet string from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Parses standard base64 text.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Base64`] when both padded and unpadded decoding
    /// fail.
    pub fn from_base64(text: &str) -> Result<Self> {
        Ok(Self(decode_base64(text)?))
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

impl AsRef<[u8]> for OctetString {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Serialize for OctetString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for OctetString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        Self::from_base64(&text).map_err(de::Error::custom)
    }
}

pub(crate) fn decode_base64(text: &str) -> Result<Vec<u8>> {
    let compact: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(&compact))
        .map_err(|err| EuiccError::Base64(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octet_string_json_uses_standard_base64() {
        // Arrange
        let bytes = OctetString::from_bytes([0xFF]);

        // Act
        let json = serde_json::to_string(&bytes).expect("octets serialize");

        // Assert
        assert_eq!(json, "\"/w==\"");
        assert_eq!(
            serde_json::from_str::<OctetString>("\"/w\"").expect("unpadded base64 deserializes"),
            bytes,
        );
    }
}
