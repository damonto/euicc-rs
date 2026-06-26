use crate::error::Result;

use super::Tlv;

/// BER-TLV encoder trait for card requests.
///
/// # Errors
///
/// Encoding can return [`EuiccError`] when required fields are missing or
/// malformed.
pub trait EncodeTlv {
    /// Encodes `self` as a BER-TLV object.
    ///
    /// # Errors
    ///
    /// Returns protocol validation or TLV construction errors.
    fn to_tlv(&self) -> Result<Tlv>;
}

/// BER-TLV decoder trait for card responses and nested structures.
///
/// # Errors
///
/// Decoding can return [`EuiccError`] when tags or child fields do not match the
/// expected structure.
pub trait DecodeTlv: Sized {
    /// Decodes a value from a BER-TLV object.
    ///
    /// # Errors
    ///
    /// Returns protocol validation or TLV traversal errors.
    fn from_tlv(tlv: &Tlv) -> Result<Self>;
}
