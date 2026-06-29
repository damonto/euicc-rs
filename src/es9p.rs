//! ES9+ JSON binding request and response types.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::bertlv::{OctetString, Tlv};
use crate::es10b::{
    AuthenticateServerRequest, LoadBoundProfilePackageRequest, PrepareDownloadRequest,
};
use crate::identifier::{HexBytes, Imei};
use crate::rsp::{ExecutionStatus, Header};
use crate::{EuiccError, Result};

/// ES9+.InitiateAuthentication endpoint path.
pub const INITIATE_AUTHENTICATION_PATH: &str = "/gsma/rsp2/es9plus/initiateAuthentication";
/// ES9+.AuthenticateClient endpoint path.
pub const AUTHENTICATE_CLIENT_PATH: &str = "/gsma/rsp2/es9plus/authenticateClient";
/// ES9+.GetBoundProfilePackage endpoint path.
pub const GET_BOUND_PROFILE_PACKAGE_PATH: &str = "/gsma/rsp2/es9plus/getBoundProfilePackage";
/// ES9+.HandleNotification endpoint path.
pub const HANDLE_NOTIFICATION_PATH: &str = "/gsma/rsp2/es9plus/handleNotification";
/// ES9+.CancelSession endpoint path.
pub const CANCEL_SESSION_PATH: &str = "/gsma/rsp2/es9plus/cancelSession";

/// Builds an ES9+ endpoint URL from a server base URL and a spec path.
///
/// # Errors
///
/// Returns [`EuiccError::Url`] when URL joining fails.
pub fn endpoint(base: &Url, path: &str) -> Result<Url> {
    base.join(path)
        .map_err(|err| EuiccError::Url(err.to_string()))
}

/// ES9+.InitiateAuthentication JSON request.
///
/// # Errors
///
/// Serialization and URL construction can return their respective errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitiateAuthenticationRequest {
    /// eUICC challenge as base64 JSON.
    #[serde(rename = "euiccChallenge")]
    pub euicc_challenge: OctetString,
    /// EUICCInfo1 as base64-encoded TLV.
    #[serde(rename = "euiccInfo1")]
    pub euicc_info1: Tlv,
    /// SM-DP+ address.
    #[serde(rename = "smdpAddress")]
    pub smdp_address: String,
}

impl InitiateAuthenticationRequest {
    /// Returns the ES9+ endpoint URL for this request.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, INITIATE_AUTHENTICATION_PATH)
    }
}

/// ES9+.InitiateAuthentication JSON response.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON, base64 TLVs, or transaction id
/// hex text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitiateAuthenticationResponse {
    /// Optional RSP response header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
    /// Transaction id as uppercase hex JSON.
    #[serde(rename = "transactionId")]
    pub transaction_id: HexBytes,
    /// ServerSigned1 TLV.
    #[serde(rename = "serverSigned1")]
    pub server_signed1: Tlv,
    /// Server signature TLV.
    #[serde(rename = "serverSignature1")]
    pub server_signature1: Tlv,
    /// CI public key identifier TLV.
    #[serde(rename = "euiccCiPKIdToBeUsed")]
    pub euicc_ci_pk_id_to_be_used: Tlv,
    /// Server certificate TLV.
    #[serde(rename = "serverCertificate")]
    pub server_certificate: Tlv,
}

impl InitiateAuthenticationResponse {
    /// Returns the optional execution status.
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.header.as_ref().and_then(Header::execution_status)
    }

    /// Builds the matching ES10b.AuthenticateServer request.
    #[must_use]
    pub fn authenticate_server_request(
        &self,
        imei: Imei,
        matching_id: Option<String>,
    ) -> AuthenticateServerRequest {
        AuthenticateServerRequest {
            transaction_id: self.transaction_id.clone(),
            signed1: self.server_signed1.clone(),
            signature1: self.server_signature1.clone(),
            used_issuer: self.euicc_ci_pk_id_to_be_used.clone(),
            certificate: self.server_certificate.clone(),
            imei,
            matching_id,
        }
    }
}

/// ES9+.AuthenticateClient JSON request.
///
/// # Errors
///
/// Serialization can fail if nested TLV encoding fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticateClientRequest {
    /// Transaction id as uppercase hex JSON.
    #[serde(rename = "transactionId")]
    pub transaction_id: HexBytes,
    /// ES10b.AuthenticateServerResponse TLV.
    #[serde(rename = "authenticateServerResponse")]
    pub authenticate_server_response: Tlv,
}

impl AuthenticateClientRequest {
    /// Returns the ES9+ endpoint URL for this request.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, AUTHENTICATE_CLIENT_PATH)
    }
}

/// ES9+.AuthenticateClient JSON response.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON, base64 TLVs, or transaction id
/// hex text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticateClientResponse {
    /// Optional RSP response header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
    /// Transaction id as uppercase hex JSON.
    #[serde(rename = "transactionId")]
    pub transaction_id: HexBytes,
    /// Optional profile metadata TLV.
    #[serde(
        rename = "profileMetadata",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub profile_metadata: Option<Tlv>,
    /// SmdpSigned2 TLV.
    #[serde(rename = "smdpSigned2")]
    pub smdp_signed2: Tlv,
    /// SM-DP+ signature TLV.
    #[serde(rename = "smdpSignature2")]
    pub smdp_signature2: Tlv,
    /// SM-DP+ certificate TLV.
    #[serde(rename = "smdpCertificate")]
    pub smdp_certificate: Tlv,
}

impl AuthenticateClientResponse {
    /// Returns the optional execution status.
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.header.as_ref().and_then(Header::execution_status)
    }

    /// Builds the matching ES10b.PrepareDownload request.
    #[must_use]
    pub fn prepare_download_request(
        &self,
        confirmation_code: Option<Vec<u8>>,
    ) -> PrepareDownloadRequest {
        PrepareDownloadRequest {
            transaction_id: self.transaction_id.clone(),
            profile_metadata: self.profile_metadata.clone(),
            signed2: self.smdp_signed2.clone(),
            signature2: self.smdp_signature2.clone(),
            certificate: self.smdp_certificate.clone(),
            confirmation_code,
        }
    }
}

/// ES9+.GetBoundProfilePackage JSON request.
///
/// # Errors
///
/// Serialization can fail if nested TLV encoding fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBoundProfilePackageRequest {
    /// Transaction id as uppercase hex JSON.
    #[serde(rename = "transactionId")]
    pub transaction_id: HexBytes,
    /// ES10b.PrepareDownloadResponse TLV.
    #[serde(rename = "prepareDownloadResponse")]
    pub prepare_download_response: Tlv,
}

impl GetBoundProfilePackageRequest {
    /// Returns the ES9+ endpoint URL for this request.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, GET_BOUND_PROFILE_PACKAGE_PATH)
    }
}

/// ES9+.GetBoundProfilePackage JSON response.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON, base64 TLVs, or transaction id
/// hex text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBoundProfilePackageResponse {
    /// Optional RSP response header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
    /// Transaction id as uppercase hex JSON.
    #[serde(rename = "transactionId")]
    pub transaction_id: HexBytes,
    /// BoundProfilePackage TLV.
    #[serde(rename = "boundProfilePackage")]
    pub bound_profile_package: Tlv,
}

impl GetBoundProfilePackageResponse {
    /// Returns the optional execution status.
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.header.as_ref().and_then(Header::execution_status)
    }

    /// Builds the matching ES10b.LoadBoundProfilePackage request.
    #[must_use]
    pub fn load_bound_profile_package_request(&self) -> LoadBoundProfilePackageRequest {
        LoadBoundProfilePackageRequest {
            bound_profile_package: self.bound_profile_package.clone(),
        }
    }
}

/// ES9+.HandleNotification JSON request.
///
/// # Errors
///
/// Serialization can fail if nested TLV encoding fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleNotificationRequest {
    /// PendingNotification TLV.
    #[serde(rename = "pendingNotification")]
    pub pending_notification: Tlv,
}

impl HandleNotificationRequest {
    /// Returns the ES9+ endpoint URL for this request.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, HANDLE_NOTIFICATION_PATH)
    }
}

/// ES9+.HandleNotification JSON response.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HandleNotificationResponse {
    /// Optional RSP response header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
}

impl HandleNotificationResponse {
    /// Returns `Executed-Success` when the response omits a header.
    #[must_use]
    pub fn execution_status(&self) -> Option<ExecutionStatus> {
        Some(
            self.header
                .as_ref()
                .and_then(Header::execution_status)
                .cloned()
                .unwrap_or_else(ExecutionStatus::success),
        )
    }
}

/// ES9+.CancelSession JSON request.
///
/// # Errors
///
/// Serialization can fail if nested TLV encoding fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelSessionRequest {
    /// Transaction id as uppercase hex JSON.
    #[serde(rename = "transactionId")]
    pub transaction_id: HexBytes,
    /// ES10b.CancelSessionResponse TLV.
    #[serde(rename = "cancelSessionResponse")]
    pub cancel_session_response: Tlv,
}

impl CancelSessionRequest {
    /// Returns the ES9+ endpoint URL for this request.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, CANCEL_SESSION_PATH)
    }
}

/// ES9+.CancelSession JSON response.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CancelSessionResponse {
    /// Optional RSP response header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
}

impl CancelSessionResponse {
    /// Returns the optional execution status.
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.header.as_ref().and_then(Header::execution_status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bertlv::{Class, Tlv};

    #[test]
    fn initiate_authentication_serializes_spec_json_names() {
        // Arrange
        let request = InitiateAuthenticationRequest {
            euicc_challenge: OctetString::from_bytes([0xAA; 16]),
            euicc_info1: Tlv::constructed(Class::ContextSpecific.constructed(32), Vec::new())
                .expect("EUICCInfo1 TLV builds"),
            smdp_address: "smdp.example".to_owned(),
        };

        // Act
        let json = serde_json::to_string(&request).expect("request serializes");

        // Assert
        assert!(json.contains("euiccChallenge"));
        assert!(json.contains("euiccInfo1"));
        assert!(json.contains("smdpAddress"));
    }

    #[test]
    fn endpoint_uses_absolute_spec_path() {
        // Arrange
        let base = Url::parse("https://smdp.example/root/").expect("URL parses");

        // Act
        let url = endpoint(&base, GET_BOUND_PROFILE_PACKAGE_PATH).expect("URL joins");

        // Assert
        assert_eq!(
            url.as_str(),
            "https://smdp.example/gsma/rsp2/es9plus/getBoundProfilePackage"
        );
    }
}
