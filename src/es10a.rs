//! ES10a card functions for SM-DP+ address configuration.

use crate::apdu::{CardRequest, CardResponse};
use crate::bertlv::{Class, DecodeTlv, EncodeTlv, Form, Tag, Tlv};
use crate::error::{EuiccError, Result};
use crate::primitive::decode_i64;

/// ES10a.GetEuiccConfiguredAddresses request.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct EuiccConfiguredAddressesRequest;

impl EncodeTlv for EuiccConfiguredAddressesRequest {
    fn to_tlv(&self) -> Result<Tlv> {
        constructed(60, Vec::new())
    }
}

impl CardRequest for EuiccConfiguredAddressesRequest {
    type Response = EuiccConfiguredAddressesResponse;

    fn decode_response(&self, tlv: &Tlv) -> Result<Self::Response> {
        EuiccConfiguredAddressesResponse::from_tlv(tlv)
    }
}

/// ES10a.GetEuiccConfiguredAddresses response.
///
/// # Errors
///
/// Decoding returns [`EuiccError::UnexpectedTag`] when the response tag is not
/// `[60]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EuiccConfiguredAddressesResponse {
    /// Default SM-DP+ address when configured.
    pub default_smdp_address: Option<String>,
    /// Root SM-DS address.
    pub root_smds_address: String,
}

impl DecodeTlv for EuiccConfiguredAddressesResponse {
    fn from_tlv(tlv: &Tlv) -> Result<Self> {
        ensure_tag(tlv, 60, "euiccConfiguredAddressesResponse")?;
        Ok(Self {
            default_smdp_address: optional_utf8(
                tlv,
                Class::ContextSpecific.primitive(0),
                "defaultDpAddress",
            )?,
            root_smds_address: required_utf8(
                tlv,
                Class::ContextSpecific.primitive(1),
                "rootDsAddress",
            )?,
        })
    }
}

impl EuiccConfiguredAddressesResponse {
    /// Decodes the response from a TLV.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::UnexpectedTag`] when the tag is not `[60]`.
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        <Self as DecodeTlv>::from_tlv(tlv)
    }
}

impl CardResponse for EuiccConfiguredAddressesResponse {}

/// ES10a.SetDefaultDpAddress request.
///
/// # Errors
///
/// Encoding returns [`EuiccError::InvalidText`] when the address exceeds the
/// one-byte APDU segment limit after UTF-8 encoding.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetDefaultDpAddressRequest {
    /// New default SM-DP+ address. Empty string removes the configured address.
    pub default_dp_address: String,
}

impl EncodeTlv for SetDefaultDpAddressRequest {
    fn to_tlv(&self) -> Result<Tlv> {
        constructed(
            63,
            vec![Tlv::primitive(
                Class::ContextSpecific.primitive(0),
                self.default_dp_address.as_bytes(),
            )?],
        )
    }
}

impl CardRequest for SetDefaultDpAddressRequest {
    type Response = SetDefaultDpAddressResponse;

    fn decode_response(&self, tlv: &Tlv) -> Result<Self::Response> {
        SetDefaultDpAddressResponse::from_tlv(tlv)
    }
}

/// Result code for SetDefaultDpAddress.
///
/// # Errors
///
/// Unknown values are represented by [`Self::Unknown`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SetDefaultDpAddressResult {
    /// Operation completed successfully.
    Ok,
    /// Undefined card error.
    UndefinedError,
    /// Unknown result code.
    Unknown(i8),
}

impl SetDefaultDpAddressResult {
    /// Decodes a signed result code.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Ok,
            127 => Self::UndefinedError,
            other => Self::Unknown(other as i8),
        }
    }
}

/// ES10a.SetDefaultDpAddress response.
///
/// # Errors
///
/// Decoding returns [`EuiccError`] when the tag or result field is malformed.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SetDefaultDpAddressResponse {
    /// Card result code.
    pub result: SetDefaultDpAddressResult,
}

impl DecodeTlv for SetDefaultDpAddressResponse {
    fn from_tlv(tlv: &Tlv) -> Result<Self> {
        ensure_tag(tlv, 63, "setDefaultDpAddressResponse")?;
        Ok(Self {
            result: SetDefaultDpAddressResult::from_i64(required_int(
                tlv,
                Class::ContextSpecific.primitive(0),
                "setDefaultDpAddressResult",
                1,
            )?),
        })
    }
}

impl SetDefaultDpAddressResponse {
    /// Decodes the response from a TLV.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the tag or result field is malformed.
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        <Self as DecodeTlv>::from_tlv(tlv)
    }
}

impl CardResponse for SetDefaultDpAddressResponse {
    fn validate(&self) -> Result<()> {
        match self.result {
            SetDefaultDpAddressResult::Ok => Ok(()),
            SetDefaultDpAddressResult::UndefinedError | SetDefaultDpAddressResult::Unknown(_) => {
                Err(EuiccError::Undefined)
            }
        }
    }
}

macro_rules! inherent_to_tlv {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl $ty {
                /// Encodes this request as an ES10 BER-TLV object.
                ///
                /// # Errors
                ///
                /// Returns protocol validation or TLV construction errors from
                /// the request-specific encoder.

                pub fn to_tlv(&self) -> Result<Tlv> {
                    <Self as EncodeTlv>::to_tlv(self)
                }
            }
        )+
    };
}

inherent_to_tlv!(EuiccConfiguredAddressesRequest, SetDefaultDpAddressRequest);

macro_rules! inherent_validate {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl $ty {
                /// Validates the decoded ES10 response.
                ///
                /// # Errors
                ///
                /// Returns a protocol-specific [`EuiccError`] for card-level
                /// failure result codes.

                pub fn validate(&self) -> Result<()> {
                    <Self as CardResponse>::validate(self)
                }
            }
        )+
    };
}

inherent_validate!(
    EuiccConfiguredAddressesResponse,
    SetDefaultDpAddressResponse
);

fn constructed(value: u64, children: Vec<Tlv>) -> Result<Tlv> {
    Tlv::constructed(Class::ContextSpecific.constructed(value), children)
}

fn ensure_tag(tlv: &Tlv, value: u64, expected: &'static str) -> Result<()> {
    if !tlv
        .tag()
        .is(Class::ContextSpecific, Form::Constructed, value)
    {
        return Err(EuiccError::UnexpectedTag {
            expected,
            actual: tlv.tag().hex(),
        });
    }
    Ok(())
}

fn required_value<'a>(parent: &'a Tlv, tag: Tag, name: &'static str) -> Result<&'a [u8]> {
    parent
        .first(&tag)
        .and_then(Tlv::value)
        .ok_or(EuiccError::MissingField(name))
}

fn required_utf8(parent: &Tlv, tag: Tag, name: &'static str) -> Result<String> {
    let value = required_value(parent, tag, name)?;
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| EuiccError::InvalidText(name))
}

fn optional_utf8(parent: &Tlv, tag: Tag, name: &'static str) -> Result<Option<String>> {
    parent
        .first(&tag)
        .and_then(Tlv::value)
        .map(|value| {
            std::str::from_utf8(value)
                .map(str::to_owned)
                .map_err(|_| EuiccError::InvalidText(name))
        })
        .transpose()
}

fn required_int(parent: &Tlv, tag: Tag, name: &'static str, max_bytes: usize) -> Result<i64> {
    decode_i64(required_value(parent, tag, name)?, max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_euicc_configured_addresses_request_matches_spec() {
        // Arrange
        let request = EuiccConfiguredAddressesRequest;

        // Act
        let bytes = request
            .to_tlv()
            .and_then(|tlv| tlv.to_bytes())
            .expect("request encodes");

        // Assert
        assert_eq!(bytes, vec![0xBF, 0x3C, 0x00]);
    }

    #[test]
    fn configured_addresses_response_decodes_context_specific_fields() {
        // Arrange
        let tlv = Tlv::constructed(
            Class::ContextSpecific.constructed(60),
            vec![
                Tlv::primitive(Class::ContextSpecific.primitive(0), b"smdp.example")
                    .expect("default address TLV builds"),
                Tlv::primitive(Class::ContextSpecific.primitive(1), b"smds.example")
                    .expect("root address TLV builds"),
            ],
        )
        .expect("response TLV builds");

        // Act
        let response = EuiccConfiguredAddressesResponse::from_tlv(&tlv).expect("response decodes");

        // Assert
        assert_eq!(
            response.default_smdp_address.as_deref(),
            Some("smdp.example")
        );
        assert_eq!(response.root_smds_address, "smds.example");
    }

    #[test]
    fn set_default_dp_address_request_matches_go_encoding() {
        // Arrange
        let request = SetDefaultDpAddressRequest {
            default_dp_address: "example.com".to_owned(),
        };

        // Act
        let bytes = request
            .to_tlv()
            .and_then(|tlv| tlv.to_bytes())
            .expect("request encodes");

        // Assert
        assert_eq!(
            bytes,
            vec![
                0xBF, 0x3F, 0x0D, 0x80, 0x0B, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm',
            ]
        );
    }

    #[test]
    fn set_default_dp_address_response_decodes_context_specific_result() {
        // Arrange
        let tlv =
            Tlv::from_bytes(&[0xBF, 0x3F, 0x03, 0x80, 0x01, 0x00]).expect("response TLV parses");

        // Act
        let response = SetDefaultDpAddressResponse::from_tlv(&tlv).expect("response decodes");

        // Assert
        assert_eq!(response.result, SetDefaultDpAddressResult::Ok);
    }
}
