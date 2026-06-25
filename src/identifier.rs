//! Identifier newtypes used by SGP.22 messages.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{EuiccError, Result};

/// assert_eq!(iccid.to_string(), "8944478600004573128");
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Iccid(Vec<u8>);

impl Iccid {
    /// Parses a text ICCID into swapped BCD bytes.
    ///
    /// # Arguments
    ///
    /// * `value` - Decimal or hexadecimal ICCID text.
    ///
    /// # Returns
    ///
    /// An [`Iccid`] containing swapped BCD bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::InvalidBcdIdentifier`] when `value` contains a
    /// non-hexadecimal character.
    ///
    /// # Examples
    ///
    /// ```
    /// let iccid = euicc::identifier::Iccid::new("89860110f9900160570")?;
    /// assert_eq!(iccid.as_bytes(), &[0x98, 0x68, 0x10, 0x01, 0x9F, 0x09, 0x10, 0x06, 0x75, 0xF0]);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn new(value: &str) -> Result<Self> {
        Ok(Self(encode_swapped_bcd(value)?))
    }

    /// Builds an ICCID from already encoded swapped BCD bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw swapped BCD bytes.
    ///
    /// # Returns
    ///
    /// An [`Iccid`] owning `bytes`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let iccid = euicc::identifier::Iccid::from_bytes([0x98, 0x44]);
    /// assert_eq!(iccid.as_bytes(), &[0x98, 0x44]);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the encoded ICCID bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Borrowed swapped BCD bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let iccid = euicc::identifier::Iccid::from_bytes([0x98, 0x44]);
    /// assert_eq!(iccid.as_bytes(), &[0x98, 0x44]);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the ICCID and returns the encoded bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Owned swapped BCD bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let bytes = euicc::identifier::Iccid::from_bytes([0x98]).into_bytes();
    /// assert_eq!(bytes, vec![0x98]);
    /// ```
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

/// assert_eq!(imei.to_string(), "123456789012345");
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Imei(Vec<u8>);

impl Imei {
    /// Parses a text IMEI into swapped BCD bytes.
    ///
    /// # Arguments
    ///
    /// * `value` - Decimal IMEI text.
    ///
    /// # Returns
    ///
    /// An [`Imei`] containing swapped BCD bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::InvalidBcdIdentifier`] when `value` contains a
    /// non-hexadecimal character.
    ///
    /// # Examples
    ///
    /// ```
    /// let imei = euicc::identifier::Imei::new("123456789012345")?;
    /// assert_eq!(imei.as_bytes().len(), 8);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn new(value: &str) -> Result<Self> {
        Ok(Self(encode_swapped_bcd(value)?))
    }

    /// Builds an IMEI from already encoded swapped BCD bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw swapped BCD bytes.
    ///
    /// # Returns
    ///
    /// An [`Imei`] owning `bytes`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let imei = euicc::identifier::Imei::from_bytes([0x21, 0x43]);
    /// assert_eq!(imei.as_bytes(), &[0x21, 0x43]);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns encoded IMEI bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Borrowed swapped BCD bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let imei = euicc::identifier::Imei::from_bytes([0x21]);
    /// assert_eq!(imei.as_bytes(), &[0x21]);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the IMEI and returns encoded bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Owned swapped BCD bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let bytes = euicc::identifier::Imei::from_bytes([0x21]).into_bytes();
    /// assert_eq!(bytes, vec![0x21]);
    /// ```
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
///
/// # Arguments
///
/// This type is built from raw AID bytes with [`IsdpAid::from_bytes`].
///
/// # Returns
///
/// A newtype for profile application identifiers.
///
/// # Errors
///
/// Constructing this type from bytes does not return errors.
///
/// # Examples
///
/// ```
/// let aid = euicc::identifier::IsdpAid::from_bytes([0xA0, 0x00]);
/// assert_eq!(aid.to_string(), "A000");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IsdpAid(Vec<u8>);

impl IsdpAid {
    /// Builds an ISD-P AID from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Application identifier bytes.
    ///
    /// # Returns
    ///
    /// An [`IsdpAid`] owning `bytes`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let aid = euicc::identifier::IsdpAid::from_bytes([0xA0, 0x00]);
    /// assert_eq!(aid.as_bytes(), &[0xA0, 0x00]);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns raw ISD-P AID bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Borrowed AID bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let aid = euicc::identifier::IsdpAid::from_bytes([0xA0]);
    /// assert_eq!(aid.as_bytes(), &[0xA0]);
    /// ```
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
/// # Arguments
///
/// This type is built from raw bytes with [`HexBytes::from_bytes`].
///
/// # Returns
///
/// A transaction-friendly byte wrapper matching SGP.22 JSON `HexString`.
///
/// # Errors
///
/// JSON deserialization returns [`EuiccError::Hex`] for invalid hexadecimal
/// text.
///
/// # Examples
///
/// ```
/// let text = serde_json::to_string(&euicc::identifier::HexBytes::from_bytes([0x0A]))?;
/// assert_eq!(text, "\"0A\"");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    /// Builds a hexadecimal byte string from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Bytes to wrap.
    ///
    /// # Returns
    ///
    /// A [`HexBytes`] value owning `bytes`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let value = euicc::identifier::HexBytes::from_bytes([0xAB]);
    /// assert_eq!(value.as_bytes(), &[0xAB]);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Parses hexadecimal text.
    ///
    /// # Arguments
    ///
    /// * `text` - Even-length hexadecimal text.
    ///
    /// # Returns
    ///
    /// A [`HexBytes`] value.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Hex`] when `text` has odd length or contains a
    /// non-hexadecimal digit.
    ///
    /// # Examples
    ///
    /// ```
    /// let value = euicc::identifier::HexBytes::from_hex("0aFF")?;
    /// assert_eq!(value.as_bytes(), &[0x0A, 0xFF]);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_hex(text: &str) -> Result<Self> {
        Ok(Self(decode_hex(text)?))
    }

    /// Returns the wrapped bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Borrowed bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let value = euicc::identifier::HexBytes::from_bytes([0xAB]);
    /// assert_eq!(value.as_bytes(), &[0xAB]);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Owned bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let bytes = euicc::identifier::HexBytes::from_bytes([0xAB]).into_bytes();
    /// assert_eq!(bytes, vec![0xAB]);
    /// ```
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

/// Encodes bytes as uppercase hexadecimal.
///
/// # Arguments
///
/// * `bytes` - Bytes to encode.
///
/// # Returns
///
/// Uppercase hexadecimal text.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// assert_eq!(euicc::identifier::encode_hex_upper(&[0x0A, 0xFF]), "0AFF");
/// ```
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
/// # Arguments
///
/// * `text` - Even-length hexadecimal text.
///
/// # Returns
///
/// Decoded bytes.
///
/// # Errors
///
/// Returns [`EuiccError::Hex`] when the text length is odd or a digit is
/// outside `[0-9A-Fa-f]`.
///
/// # Examples
///
/// ```
/// assert_eq!(euicc::identifier::decode_hex("0aff")?, vec![0x0A, 0xFF]);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
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

/// Byte string serialized as base64 JSON text.
///
/// # Arguments
///
/// This type is built from raw bytes with [`OctetString::from_bytes`].
///
/// # Returns
///
/// A JSON-friendly octet string matching Go's `[]byte` JSON encoding.
///
/// # Errors
///
/// JSON deserialization returns [`EuiccError::Base64`] when text cannot be
/// decoded with padded or unpadded standard base64.
///
/// # Examples
///
/// ```
/// let text = serde_json::to_string(&euicc::identifier::OctetString::from_bytes([0xFF]))?;
/// assert_eq!(text, "\"/w==\"");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct OctetString(Vec<u8>);

impl OctetString {
    /// Builds an octet string from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Bytes to wrap.
    ///
    /// # Returns
    ///
    /// An [`OctetString`] value owning `bytes`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let value = euicc::identifier::OctetString::from_bytes([0xFF]);
    /// assert_eq!(value.as_bytes(), &[0xFF]);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Parses standard base64 text.
    ///
    /// # Arguments
    ///
    /// * `text` - Padded or unpadded standard base64 text. ASCII whitespace is
    ///   ignored for compatibility with existing fixtures.
    ///
    /// # Returns
    ///
    /// An [`OctetString`] value.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Base64`] when both padded and unpadded decoding
    /// fail.
    ///
    /// # Examples
    ///
    /// ```
    /// let value = euicc::identifier::OctetString::from_base64("/w")?;
    /// assert_eq!(value.as_bytes(), &[0xFF]);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_base64(text: &str) -> Result<Self> {
        Ok(Self(decode_base64(text)?))
    }

    /// Returns the wrapped bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Borrowed bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let value = euicc::identifier::OctetString::from_bytes([0xFF]);
    /// assert_eq!(value.as_bytes(), &[0xFF]);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Owned bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let bytes = euicc::identifier::OctetString::from_bytes([0xFF]).into_bytes();
    /// assert_eq!(bytes, vec![0xFF]);
    /// ```
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

/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProfileClass {
    /// Test profile.
    Test,
    /// Provisioning profile.
    Provisioning,
    /// Operational profile.
    Operational,
    /// Unknown profile class value.
    Unknown(i8),
}

impl ProfileClass {
    /// Decodes a signed integer profile class.
    ///
    /// # Arguments
    ///
    /// * `value` - Signed integer value from the card.
    ///
    /// # Returns
    ///
    /// A typed profile class, preserving unknown values.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::identifier::ProfileClass::from_i64(1),
    ///     euicc::identifier::ProfileClass::Provisioning,
    /// );
    /// ```
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Test,
            1 => Self::Provisioning,
            2 => Self::Operational,
            other => Self::Unknown(other as i8),
        }
    }

    /// Returns a human-readable class label.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// A short lowercase profile class label.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(euicc::identifier::ProfileClass::Test.as_str(), "test");
    /// ```
    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            Self::Test => "test".to_owned(),
            Self::Provisioning => "provisioning".to_owned(),
            Self::Operational => "operational".to_owned(),
            Self::Unknown(value) => format!("unknown({value})"),
        }
    }
}

impl fmt::Display for ProfileClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
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

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(EuiccError::Hex(format!("invalid digit 0x{other:02X}"))),
    }
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
    fn json_wrappers_match_go_encoding() {
        // Arrange
        let hex = HexBytes::from_bytes([0x0A, 0xFF]);
        let bytes = OctetString::from_bytes([0xFF]);

        // Act
        let hex_json = serde_json::to_string(&hex).expect("hex serializes");
        let bytes_json = serde_json::to_string(&bytes).expect("octets serialize");

        // Assert
        assert_eq!(hex_json, "\"0AFF\"");
        assert_eq!(bytes_json, "\"/w==\"");
        assert_eq!(
            serde_json::from_str::<HexBytes>(&hex_json).expect("hex deserializes"),
            hex,
        );
        assert_eq!(
            serde_json::from_str::<OctetString>("\"/w\"").expect("unpadded base64 deserializes"),
            bytes,
        );
    }
}
