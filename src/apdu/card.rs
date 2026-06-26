use crate::bertlv::{EncodeTlv, Tlv};
use crate::error::Result;

/// Card response trait.
///
/// # Errors
///
/// Validation returns [`EuiccError`] for non-success card result codes.
pub trait CardResponse {
    /// Validates the decoded card response.
    ///
    /// # Errors
    ///
    /// Returns a protocol-specific [`EuiccError`] for card-level failures.
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Card request trait for ES10 APDU commands.
///
/// # Errors
///
/// Encoding and response decoding return [`EuiccError`] on malformed input or
/// card failure status.
pub trait CardRequest: EncodeTlv {
    /// Response type returned by the card.
    type Response: CardResponse;

    /// Decodes a response TLV for this request.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the response tag or payload is malformed.
    ///
    /// # struct Response;
    /// # impl euicc::apdu::CardResponse for Response {}
    /// # struct Request;
    /// # impl euicc::bertlv::EncodeTlv for Request {
    /// #     fn to_tlv(&self) -> euicc::Result<euicc::bertlv::Tlv> {
    /// #         euicc::bertlv::Tlv::constructed(
    /// #             euicc::bertlv::Class::ContextSpecific.constructed(46),
    /// #             Vec::new(),
    /// #         )
    fn decode_response(&self, tlv: &Tlv) -> Result<Self::Response>;
}
