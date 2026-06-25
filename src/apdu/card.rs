use crate::bertlv::{EncodeTlv, Tlv};
use crate::error::Result;

/// Card response trait.
///
/// # Arguments
///
/// Implementors validate protocol-specific status fields after TLV decoding.
///
/// # Returns
///
/// A typed trait used by [`EuiccApdu::transmit`].
///
/// # Errors
///
/// Validation returns [`EuiccError`] for non-success card result codes.
///
/// # Examples
///
/// ```
/// #[derive(Debug)]
/// struct Response;
/// impl euicc::apdu::CardResponse for Response {}
/// ```
pub trait CardResponse {
    /// Validates the decoded card response.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the decoded response represents success.
    ///
    /// # Errors
    ///
    /// Returns a protocol-specific [`EuiccError`] for card-level failures.
    ///
    /// # Examples
    ///
    /// ```
    /// use euicc::apdu::CardResponse;
    ///
    /// struct Response;
    /// impl euicc::apdu::CardResponse for Response {}
    /// Response.validate()?;
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Card request trait for ES10 APDU commands.
///
/// # Arguments
///
/// Implementors encode themselves as BER-TLV and decode their matching response.
///
/// # Returns
///
/// A typed request trait consumed by [`EuiccApdu::transmit`].
///
/// # Errors
///
/// Encoding and response decoding return [`EuiccError`] on malformed input or
/// card failure status.
///
/// # Examples
///
/// ```
/// struct Request;
/// struct Response;
///
/// impl euicc::apdu::CardResponse for Response {}
/// impl euicc::bertlv::EncodeTlv for Request {
///     fn to_tlv(&self) -> euicc::Result<euicc::bertlv::Tlv> {
///         euicc::bertlv::Tlv::constructed(
///             euicc::bertlv::Class::ContextSpecific.constructed(46),
///             Vec::new(),
///         )
///     }
/// }
/// impl euicc::apdu::CardRequest for Request {
///     type Response = Response;
///
///     fn decode_response(&self, _tlv: &euicc::bertlv::Tlv) -> euicc::Result<Self::Response> {
///         Ok(Response)
///     }
/// }
/// ```
pub trait CardRequest: EncodeTlv {
    /// Response type returned by the card.
    type Response: CardResponse;

    /// Decodes a response TLV for this request.
    ///
    /// # Arguments
    ///
    /// * `tlv` - Response TLV returned by the eUICC.
    ///
    /// # Returns
    ///
    /// Decoded response.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the response tag or payload is malformed.
    ///
    /// # Examples
    ///
    /// ```
    /// # struct Response;
    /// # impl euicc::apdu::CardResponse for Response {}
    /// # struct Request;
    /// # impl euicc::bertlv::EncodeTlv for Request {
    /// #     fn to_tlv(&self) -> euicc::Result<euicc::bertlv::Tlv> {
    /// #         euicc::bertlv::Tlv::constructed(
    /// #             euicc::bertlv::Class::ContextSpecific.constructed(46),
    /// #             Vec::new(),
    /// #         )
    /// #     }
    /// # }
    /// # impl euicc::apdu::CardRequest for Request {
    /// #     type Response = Response;
    /// fn decode_response(&self, _tlv: &euicc::bertlv::Tlv) -> euicc::Result<Self::Response> {
    ///     Ok(Response)
    /// }
    /// # }
    /// ```
    fn decode_response(&self, tlv: &Tlv) -> Result<Self::Response>;
}
