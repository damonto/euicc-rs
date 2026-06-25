use crate::error::Result;

use super::Tlv;

/// BER-TLV encoder trait for card requests.
///
/// # Arguments
///
/// Implementors produce a complete TLV object.
///
/// # Returns
///
/// A typed trait used by card request dispatch.
///
/// # Errors
///
/// Encoding can return [`EuiccError`] when required fields are missing or
/// malformed.
///
/// # Examples
///
/// ```
/// struct Empty;
/// impl euicc::bertlv::EncodeTlv for Empty {
///     fn to_tlv(&self) -> euicc::Result<euicc::bertlv::Tlv> {
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(46),
///             Vec::new(),
///         )
///     }
/// }
/// ```
pub trait EncodeTlv {
    /// Encodes `self` as a BER-TLV object.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// The encoded TLV tree.
    ///
    /// # Errors
    ///
    /// Returns protocol validation or TLV construction errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use euicc::bertlv::EncodeTlv;
    ///
    /// struct Empty;
    /// impl euicc::bertlv::EncodeTlv for Empty {
    ///     fn to_tlv(&self) -> euicc::Result<euicc::bertlv::Tlv> {
    ///         euicc::bertlv::Tlv::constructed(
    ///             euicc::bertlv::Class::ContextSpecific.constructed(46),
    ///             Vec::new(),
    ///         )
    ///     }
    /// }
    /// let tlv = Empty.to_tlv()?;
    /// assert_eq!(tlv.tag().value(), 46);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    fn to_tlv(&self) -> Result<Tlv>;
}

/// BER-TLV decoder trait for card responses and nested structures.
///
/// # Arguments
///
/// Implementors decode from a borrowed [`Tlv`].
///
/// # Returns
///
/// A typed trait used by card response dispatch.
///
/// # Errors
///
/// Decoding can return [`EuiccError`] when tags or child fields do not match the
/// expected structure.
///
/// # Examples
///
/// ```
/// struct Empty;
/// impl euicc::bertlv::DecodeTlv for Empty {
///     fn from_tlv(tlv: &euicc::bertlv::Tlv) -> euicc::Result<Self> {
///         if tlv.tag().value() == 46 { Ok(Self) } else { Err(euicc::EuiccError::MissingField("tag")) }
///     }
/// }
/// ```
pub trait DecodeTlv: Sized {
    /// Decodes a value from a BER-TLV object.
    ///
    /// # Arguments
    ///
    /// * `tlv` - Source TLV.
    ///
    /// # Returns
    ///
    /// Decoded value.
    ///
    /// # Errors
    ///
    /// Returns protocol validation or TLV traversal errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use euicc::bertlv::DecodeTlv;
    ///
    /// struct Empty;
    /// impl euicc::bertlv::DecodeTlv for Empty {
    ///     fn from_tlv(tlv: &euicc::bertlv::Tlv) -> euicc::Result<Self> {
    ///         if tlv.tag().value() == 46 { Ok(Self) } else { Err(euicc::EuiccError::MissingField("tag")) }
    ///     }
    /// }
    /// let tlv = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(46),
    ///     Vec::new(),
    /// )?;
    /// let _decoded = Empty::from_tlv(&tlv)?;
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    fn from_tlv(tlv: &Tlv) -> Result<Self>;
}
