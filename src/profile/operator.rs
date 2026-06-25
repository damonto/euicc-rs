use crate::bertlv::{Class, Form, Tlv};
use crate::error::{EuiccError, Result};

use super::tlv::{optional_value, required_value};

/// Operator identifier decoded from profile owner TLV data.
///
/// # Arguments
///
/// Use [`OperatorId::from_tlv`] to decode from `context-specific constructed
/// 23`.
///
/// # Returns
///
/// Mandatory PLMN plus optional GID1 and GID2 values.
///
/// # Errors
///
/// Decoding returns [`EuiccError::UnexpectedTag`] when the TLV tag is not the
/// profile-owner tag.
///
/// # Examples
///
/// ```
/// let operator = euicc::profile::OperatorId {
///     plmn: vec![0x13, 0xF2, 0x60],
///     gid1: None,
///     gid2: None,
/// };
/// assert_eq!(operator.mcc().as_deref(), Some("312"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperatorId {
    /// MCC/MNC bytes in 3GPP PLMN format.
    pub plmn: Vec<u8>,
    /// GID1 bytes when present.
    pub gid1: Option<Vec<u8>>,
    /// GID2 bytes when present.
    pub gid2: Option<Vec<u8>>,
}

impl OperatorId {
    /// Decodes an operator id from a TLV.
    ///
    /// # Arguments
    ///
    /// * `tlv` - `context-specific constructed 23` profile owner TLV.
    ///
    /// # Returns
    ///
    /// A decoded [`OperatorId`].
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::UnexpectedTag`] when the tag is not the expected
    /// profile-owner tag.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(23),
    ///     vec![euicc::bertlv::Tlv::primitive(
    ///         euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///         [0x13, 0xF2, 0x60],
    ///     )?],
    /// )?;
    /// let operator = euicc::profile::OperatorId::from_tlv(&tlv)?;
    /// assert_eq!(operator.mcc().as_deref(), Some("312"));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        if !tlv.tag().is(Class::ContextSpecific, Form::Constructed, 23) {
            return Err(EuiccError::UnexpectedTag {
                expected: "profileOwner",
                actual: tlv.tag().hex(),
            });
        }
        let plmn = required_value(tlv, Class::ContextSpecific.primitive(0), "mccMnc")?.to_vec();
        let gid1 = optional_value(tlv, Class::ContextSpecific.primitive(1)).map(ToOwned::to_owned);
        let gid2 = optional_value(tlv, Class::ContextSpecific.primitive(2)).map(ToOwned::to_owned);

        Ok(Self { plmn, gid1, gid2 })
    }

    /// Returns the decoded MCC.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Some(String)` when at least two PLMN bytes are present, otherwise
    /// `None`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let operator = euicc::profile::OperatorId {
    ///     plmn: vec![0x13, 0xF2, 0x60],
    ///     gid1: None,
    ///     gid2: None,
    /// };
    /// assert_eq!(operator.mcc().as_deref(), Some("312"));
    /// ```
    #[must_use]
    pub fn mcc(&self) -> Option<String> {
        let plmn = &self.plmn;
        if plmn.len() < 2 {
            return None;
        }
        Some(
            String::from_utf8_lossy(&[
                b'0' + (plmn[0] & 0x0F),
                b'0' + (plmn[0] >> 4),
                b'0' + (plmn[1] & 0x0F),
            ])
            .into_owned(),
        )
    }

    /// Returns the decoded MNC.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Some(String)` when at least three PLMN bytes are present, otherwise
    /// `None`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let operator = euicc::profile::OperatorId {
    ///     plmn: vec![0x13, 0xF2, 0x60],
    ///     gid1: None,
    ///     gid2: None,
    /// };
    /// assert_eq!(operator.mnc().as_deref(), Some("06"));
    /// ```
    #[must_use]
    pub fn mnc(&self) -> Option<String> {
        let plmn = &self.plmn;
        if plmn.len() < 3 {
            return None;
        }
        let mut mnc = Vec::with_capacity(3);
        mnc.push(b'0' + (plmn[2] & 0x0F));
        mnc.push(b'0' + (plmn[2] >> 4));
        let third = plmn[1] >> 4;
        if third != 0x0F {
            mnc.push(b'0' + third);
        }
        Some(String::from_utf8_lossy(&mnc).into_owned())
    }
}
