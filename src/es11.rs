//! ES11 JSON binding request and response types.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::identifier::HexBytes;
use crate::rsp::{ExecutionStatus, Header};
use crate::{EuiccError, Result};

/// ES11.InitiateAuthentication JSON request.
///
/// # Errors
///
/// Serialization and URL construction can return their respective errors.
pub type InitiateAuthenticationRequest = crate::es9p::InitiateAuthenticationRequest;

/// ES11.InitiateAuthentication JSON response.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON, base64 TLVs, or transaction id
/// hex text.
pub type InitiateAuthenticationResponse = crate::es9p::InitiateAuthenticationResponse;

/// ES11.AuthenticateClient JSON request.
///
/// # Errors
///
/// Serialization can fail if nested TLV encoding fails.
pub type AuthenticateClientRequest = crate::es9p::AuthenticateClientRequest;

/// ES11 event entry returned by AuthenticateClient.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON field types.
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
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when the address cannot be parsed as a URL.
    pub fn url(&self) -> Result<Url> {
        let text = format!("https://{}", self.rsp_server_address);
        Url::parse(&text).map_err(|err| EuiccError::Url(err.to_string()))
    }
}

/// ES11.AuthenticateClient JSON response.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON or transaction id hex text.
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
