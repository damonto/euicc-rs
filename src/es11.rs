//! ES11 JSON binding request and response types.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::identifier::HexBytes;
use crate::rsp::{ExecutionStatus, Header};
use crate::{EuiccError, Result};

/// ES11.InitiateAuthentication JSON request.
///
/// # Arguments
///
/// This type is identical to [`crate::es9p::InitiateAuthenticationRequest`]
/// because SGP.22 defines the ES11 request body as the ES9+ body.
///
/// # Returns
///
/// A serializable InitiateAuthentication request body.
///
/// # Errors
///
/// Serialization and URL construction can return their respective errors.
///
/// # Examples
///
/// ```
/// let request = euicc::es11::InitiateAuthenticationRequest {
///     euicc_challenge: euicc::identifier::OctetString::from_bytes([0xAA; 16]),
///     euicc_info1: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::ContextSpecific.constructed(32),
///         Vec::new(),
///     )?,
///     smdp_address: "smds.example".to_owned(),
/// };
/// assert!(serde_json::to_string(&request)?.contains("euiccChallenge"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub type InitiateAuthenticationRequest = crate::es9p::InitiateAuthenticationRequest;

/// ES11.InitiateAuthentication JSON response.
///
/// # Arguments
///
/// This type is identical to [`crate::es9p::InitiateAuthenticationResponse`]
/// because SGP.22 defines the ES11 response body as the ES9+ body.
///
/// # Returns
///
/// Server authentication material for ES10b.AuthenticateServer.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON, base64 TLVs, or transaction id
/// hex text.
///
/// # Examples
///
/// ```
/// let response = euicc::es11::InitiateAuthenticationResponse {
///     header: None,
///     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
///     server_signed1: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::Universal.constructed(16),
///         Vec::new(),
///     )?,
///     server_signature1: euicc::bertlv::Tlv::primitive(
///         euicc::bertlv::Class::Application.primitive(55),
///         [],
///     )?,
///     euicc_ci_pk_id_to_be_used: euicc::bertlv::Tlv::primitive(
///         euicc::bertlv::Class::Universal.primitive(4),
///         [],
///     )?,
///     server_certificate: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::Universal.constructed(16),
///         Vec::new(),
///     )?,
/// };
/// assert_eq!(response.transaction_id.as_bytes(), &[0x01]);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
pub type InitiateAuthenticationResponse = crate::es9p::InitiateAuthenticationResponse;

/// ES11.AuthenticateClient JSON request.
///
/// # Arguments
///
/// This type is identical to [`crate::es9p::AuthenticateClientRequest`] because
/// SGP.22 defines the ES11 request body as the ES9+ body.
///
/// # Returns
///
/// A serializable AuthenticateClient request body.
///
/// # Errors
///
/// Serialization can fail if nested TLV encoding fails.
///
/// # Examples
///
/// ```
/// let request = euicc::es11::AuthenticateClientRequest {
///     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
///     authenticate_server_response: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::ContextSpecific.constructed(56),
///         Vec::new(),
///     )?,
/// };
/// assert!(serde_json::to_string(&request)?.contains("authenticateServerResponse"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub type AuthenticateClientRequest = crate::es9p::AuthenticateClientRequest;

/// ES11 event entry returned by AuthenticateClient.
///
/// # Arguments
///
/// This struct is deserialized from one JSON `eventEntries` item.
///
/// # Returns
///
/// Event identifier and RSP server address.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON field types.
///
/// # Examples
///
/// ```
/// let entry = euicc::es11::EventEntry {
///     event_id: "event-1".to_owned(),
///     rsp_server_address: "smdp.example".to_owned(),
/// };
/// assert_eq!(entry.url()?.as_str(), "https://smdp.example/");
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEntry {
    /// Identification of the event.
    #[serde(rename = "eventId")]
    pub event_id: String,
    /// RSP server address where the event can be found.
    #[serde(rename = "rspServerAddress")]
    pub rsp_server_address: String,
}

impl EventEntry {
    /// Builds an HTTPS URL for the RSP server address.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// A URL using `https` and the RSP server address as the host.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when the address cannot be parsed as a URL.
    ///
    /// # Examples
    ///
    /// ```
    /// let entry = euicc::es11::EventEntry {
    ///     event_id: "event-1".to_owned(),
    ///     rsp_server_address: "smdp.example".to_owned(),
    /// };
    /// assert_eq!(entry.url()?.host_str(), Some("smdp.example"));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn url(&self) -> Result<Url> {
        let text = format!("https://{}", self.rsp_server_address);
        Url::parse(&text).map_err(|err| EuiccError::Url(err.to_string()))
    }
}

/// ES11.AuthenticateClient JSON response.
///
/// # Arguments
///
/// This struct is deserialized from the SM-DS JSON response body.
///
/// # Returns
///
/// Transaction id plus event entries that point to RSP servers.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON or transaction id hex text.
///
/// # Examples
///
/// ```
/// let response = euicc::es11::AuthenticateClientResponse {
///     header: None,
///     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
///     event_entries: vec![euicc::es11::EventEntry {
///         event_id: "event-1".to_owned(),
///         rsp_server_address: "smdp.example".to_owned(),
///     }],
/// };
/// assert_eq!(response.event_entries.len(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticateClientResponse {
    /// Optional RSP response header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
    /// Transaction id as uppercase hex JSON.
    #[serde(rename = "transactionId")]
    pub transaction_id: HexBytes,
    /// Event entries returned by the SM-DS.
    #[serde(rename = "eventEntries")]
    pub event_entries: Vec<EventEntry>,
}

impl AuthenticateClientResponse {
    /// Returns the optional execution status.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// The execution status when a header is present.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let response = euicc::es11::AuthenticateClientResponse {
    ///     header: None,
    ///     transaction_id: euicc::identifier::HexBytes::default(),
    ///     event_entries: Vec::new(),
    /// };
    /// assert!(response.execution_status().is_none());
    /// ```
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.header.as_ref().and_then(Header::execution_status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_client_response_uses_es11_json_names() {
        // Arrange
        let response = AuthenticateClientResponse {
            header: None,
            transaction_id: HexBytes::from_bytes([0x01]),
            event_entries: vec![EventEntry {
                event_id: "event-1".to_owned(),
                rsp_server_address: "smdp.example".to_owned(),
            }],
        };

        // Act
        let json = serde_json::to_string(&response).expect("response serializes");

        // Assert
        assert!(json.contains("transactionId"));
        assert!(json.contains("eventEntries"));
        assert!(json.contains("rspServerAddress"));
    }
}
