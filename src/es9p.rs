//! ES9+ JSON binding request and response types.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::bertlv::Tlv;
use crate::es10b::{
    AuthenticateServerRequest, LoadBoundProfilePackageRequest, PrepareDownloadRequest,
};
use crate::identifier::{HexBytes, Imei, OctetString};
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
/// # Arguments
///
/// * `base` - SM-DP+ base URL, such as `https://smdp.example`.
/// * `path` - Absolute ES9+ path constant.
///
/// # Returns
///
/// A URL pointing at the requested ES9+ function.
///
/// # Errors
///
/// Returns [`EuiccError::Url`] when URL joining fails.
///
/// # Examples
///
/// ```
/// let base = url::Url::parse("https://smdp.example/root/")?;
/// let url = euicc::es9p::endpoint(&base, euicc::es9p::AUTHENTICATE_CLIENT_PATH)?;
/// assert_eq!(url.as_str(), "https://smdp.example/gsma/rsp2/es9plus/authenticateClient");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn endpoint(base: &Url, path: &str) -> Result<Url> {
    base.join(path)
        .map_err(|err| EuiccError::Url(err.to_string()))
}

/// ES9+.InitiateAuthentication JSON request.
///
/// # Arguments
///
/// Build this struct from ES10b.GetEuiccChallenge and ES10b.GetEUICCInfo1 data.
///
/// # Returns
///
/// A serializable request body with base64 binary fields.
///
/// # Errors
///
/// Serialization and URL construction can return their respective errors.
///
/// # Examples
///
/// ```
/// let request = euicc::es9p::InitiateAuthenticationRequest {
///     euicc_challenge: euicc::identifier::OctetString::from_bytes([0xAA; 16]),
///     euicc_info1: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::ContextSpecific.constructed(32),
///         Vec::new(),
///     )?,
///     smdp_address: "smdp.example".to_owned(),
/// };
/// assert!(serde_json::to_string(&request)?.contains("euiccChallenge"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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
    /// # Arguments
    ///
    /// * `base` - SM-DP+ base URL.
    ///
    /// # Returns
    ///
    /// The InitiateAuthentication URL.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let request = euicc::es9p::InitiateAuthenticationRequest {
    ///     euicc_challenge: euicc::identifier::OctetString::from_bytes([0xAA; 16]),
    ///     euicc_info1: euicc::bertlv::Tlv::constructed(
    ///         euicc::bertlv::Class::ContextSpecific.constructed(32),
    ///         Vec::new(),
    ///     )?,
    ///     smdp_address: "smdp.example".to_owned(),
    /// };
    /// let base = url::Url::parse("https://smdp.example")?;
    /// assert!(request.url(&base)?.path().ends_with("/initiateAuthentication"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, INITIATE_AUTHENTICATION_PATH)
    }
}

/// ES9+.InitiateAuthentication JSON response.
///
/// # Arguments
///
/// This struct is deserialized from the SM-DP+ JSON response body.
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
/// let response = euicc::es9p::InitiateAuthenticationResponse {
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
    /// let response = euicc::es9p::InitiateAuthenticationResponse {
    ///     header: None,
    ///     transaction_id: euicc::identifier::HexBytes::default(),
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
    /// assert!(response.execution_status().is_none());
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.header.as_ref().and_then(Header::execution_status)
    }

    /// Builds the matching ES10b.AuthenticateServer request.
    ///
    /// # Arguments
    ///
    /// * `imei` - Device IMEI encoded for DeviceInfo.
    /// * `matching_id` - Optional activation-code matching id.
    ///
    /// # Returns
    ///
    /// An ES10b.AuthenticateServer request populated from this response.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// # let response = euicc::es9p::InitiateAuthenticationResponse {
    /// #     header: None,
    /// #     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
    /// #     server_signed1: euicc::bertlv::Tlv::constructed(
    /// #         euicc::bertlv::Class::Universal.constructed(16),
    /// #         Vec::new(),
    /// #     )?,
    /// #     server_signature1: euicc::bertlv::Tlv::primitive(
    /// #         euicc::bertlv::Class::Application.primitive(55),
    /// #         [],
    /// #     )?,
    /// #     euicc_ci_pk_id_to_be_used: euicc::bertlv::Tlv::primitive(
    /// #         euicc::bertlv::Class::Universal.primitive(4),
    /// #         [],
    /// #     )?,
    /// #     server_certificate: euicc::bertlv::Tlv::constructed(
    /// #         euicc::bertlv::Class::Universal.constructed(16),
    /// #         Vec::new(),
    /// #     )?,
    /// # };
    /// let request = response.authenticate_server_request(
    ///     euicc::identifier::Imei::new("123456789012345")?,
    ///     None,
    /// );
    /// assert_eq!(request.transaction_id.as_bytes(), &[0x01]);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
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
/// # Arguments
///
/// Build from an ES10b.AuthenticateServer response TLV.
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
/// let request = euicc::es9p::AuthenticateClientRequest {
///     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
///     authenticate_server_response: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::ContextSpecific.constructed(56),
///         Vec::new(),
///     )?,
/// };
/// assert!(serde_json::to_string(&request)?.contains("authenticateServerResponse"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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
    /// # Arguments
    ///
    /// * `base` - SM-DP+ base URL.
    ///
    /// # Returns
    ///
    /// The AuthenticateClient URL.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let request = euicc::es9p::AuthenticateClientRequest {
    ///     transaction_id: euicc::identifier::HexBytes::default(),
    ///     authenticate_server_response: euicc::bertlv::Tlv::constructed(
    ///         euicc::bertlv::Class::ContextSpecific.constructed(56),
    ///         Vec::new(),
    ///     )?,
    /// };
    /// let base = url::Url::parse("https://smdp.example")?;
    /// assert!(request.url(&base)?.path().ends_with("/authenticateClient"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, AUTHENTICATE_CLIENT_PATH)
    }
}

/// ES9+.AuthenticateClient JSON response.
///
/// # Arguments
///
/// This struct is deserialized from the SM-DP+ JSON response body.
///
/// # Returns
///
/// Profile metadata and SM-DP+ data for ES10b.PrepareDownload.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON, base64 TLVs, or transaction id
/// hex text.
///
/// # Examples
///
/// ```
/// let response = euicc::es9p::AuthenticateClientResponse {
///     header: None,
///     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
///     profile_metadata: None,
///     smdp_signed2: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::Universal.constructed(16),
///         Vec::new(),
///     )?,
///     smdp_signature2: euicc::bertlv::Tlv::primitive(
///         euicc::bertlv::Class::Application.primitive(55),
///         [],
///     )?,
///     smdp_certificate: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::Universal.constructed(16),
///         Vec::new(),
///     )?,
/// };
/// assert_eq!(response.transaction_id.as_bytes(), &[0x01]);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
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
    /// let response = euicc::es9p::AuthenticateClientResponse {
    ///     header: Some(euicc::rsp::Header {
    ///         execution_status: Some(euicc::rsp::ExecutionStatus::success()),
    ///         requester_id: None,
    ///         call_id: None,
    ///     }),
    ///     transaction_id: euicc::identifier::HexBytes::default(),
    ///     profile_metadata: None,
    ///     smdp_signed2: euicc::bertlv::Tlv::constructed(
    ///         euicc::bertlv::Class::Universal.constructed(16),
    ///         Vec::new(),
    ///     )?,
    ///     smdp_signature2: euicc::bertlv::Tlv::primitive(
    ///         euicc::bertlv::Class::Application.primitive(55),
    ///         [],
    ///     )?,
    ///     smdp_certificate: euicc::bertlv::Tlv::constructed(
    ///         euicc::bertlv::Class::Universal.constructed(16),
    ///         Vec::new(),
    ///     )?,
    /// };
    /// assert!(response.execution_status().is_some_and(|status| status.executed_success()));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.header.as_ref().and_then(Header::execution_status)
    }

    /// Builds the matching ES10b.PrepareDownload request.
    ///
    /// # Arguments
    ///
    /// * `confirmation_code` - Optional user confirmation code bytes.
    ///
    /// # Returns
    ///
    /// An ES10b.PrepareDownload request.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// # let response = euicc::es9p::AuthenticateClientResponse {
    /// #     header: None,
    /// #     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
    /// #     profile_metadata: None,
    /// #     smdp_signed2: euicc::bertlv::Tlv::constructed(
    /// #         euicc::bertlv::Class::Universal.constructed(16),
    /// #         Vec::new(),
    /// #     )?,
    /// #     smdp_signature2: euicc::bertlv::Tlv::primitive(
    /// #         euicc::bertlv::Class::Application.primitive(55),
    /// #         [],
    /// #     )?,
    /// #     smdp_certificate: euicc::bertlv::Tlv::constructed(
    /// #         euicc::bertlv::Class::Universal.constructed(16),
    /// #         Vec::new(),
    /// #     )?,
    /// # };
    /// let request = response.prepare_download_request(None);
    /// assert_eq!(request.transaction_id.as_bytes(), &[0x01]);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
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
/// # Arguments
///
/// Build from an ES10b.PrepareDownload response TLV.
///
/// # Returns
///
/// A serializable GetBoundProfilePackage request body.
///
/// # Errors
///
/// Serialization can fail if nested TLV encoding fails.
///
/// # Examples
///
/// ```
/// let request = euicc::es9p::GetBoundProfilePackageRequest {
///     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
///     prepare_download_response: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::ContextSpecific.constructed(33),
///         Vec::new(),
///     )?,
/// };
/// assert!(serde_json::to_string(&request)?.contains("prepareDownloadResponse"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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
    /// # Arguments
    ///
    /// * `base` - SM-DP+ base URL.
    ///
    /// # Returns
    ///
    /// The GetBoundProfilePackage URL.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let request = euicc::es9p::GetBoundProfilePackageRequest {
    ///     transaction_id: euicc::identifier::HexBytes::default(),
    ///     prepare_download_response: euicc::bertlv::Tlv::constructed(
    ///         euicc::bertlv::Class::ContextSpecific.constructed(33),
    ///         Vec::new(),
    ///     )?,
    /// };
    /// let base = url::Url::parse("https://smdp.example")?;
    /// assert!(request.url(&base)?.path().ends_with("/getBoundProfilePackage"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, GET_BOUND_PROFILE_PACKAGE_PATH)
    }
}

/// ES9+.GetBoundProfilePackage JSON response.
///
/// # Arguments
///
/// This struct is deserialized from the SM-DP+ JSON response body.
///
/// # Returns
///
/// A BoundProfilePackage TLV for ES10b.LoadBoundProfilePackage.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON, base64 TLVs, or transaction id
/// hex text.
///
/// # Examples
///
/// ```
/// let response = euicc::es9p::GetBoundProfilePackageResponse {
///     header: None,
///     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
///     bound_profile_package: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::ContextSpecific.constructed(54),
///         Vec::new(),
///     )?,
/// };
/// assert_eq!(response.bound_profile_package.tag().value(), 54);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
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
    /// let response = euicc::es9p::GetBoundProfilePackageResponse {
    ///     header: None,
    ///     transaction_id: euicc::identifier::HexBytes::default(),
    ///     bound_profile_package: euicc::bertlv::Tlv::constructed(
    ///         euicc::bertlv::Class::ContextSpecific.constructed(54),
    ///         Vec::new(),
    ///     )?,
    /// };
    /// assert!(response.execution_status().is_none());
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.header.as_ref().and_then(Header::execution_status)
    }

    /// Builds the matching ES10b.LoadBoundProfilePackage request.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// An ES10b.LoadBoundProfilePackage request.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let response = euicc::es9p::GetBoundProfilePackageResponse {
    ///     header: None,
    ///     transaction_id: euicc::identifier::HexBytes::default(),
    ///     bound_profile_package: euicc::bertlv::Tlv::constructed(
    ///         euicc::bertlv::Class::ContextSpecific.constructed(54),
    ///         Vec::new(),
    ///     )?,
    /// };
    /// assert_eq!(response.load_bound_profile_package_request().bound_profile_package.tag().value(), 54);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn load_bound_profile_package_request(&self) -> LoadBoundProfilePackageRequest {
        LoadBoundProfilePackageRequest {
            bound_profile_package: self.bound_profile_package.clone(),
        }
    }
}

/// ES9+.HandleNotification JSON request.
///
/// # Arguments
///
/// Build from a `PendingNotification` TLV returned by ES10b.RetrieveNotificationsList.
///
/// # Returns
///
/// A serializable HandleNotification request body.
///
/// # Errors
///
/// Serialization can fail if nested TLV encoding fails.
///
/// # Examples
///
/// ```
/// let request = euicc::es9p::HandleNotificationRequest {
///     pending_notification: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::Universal.constructed(16),
///         Vec::new(),
///     )?,
/// };
/// assert!(serde_json::to_string(&request)?.contains("pendingNotification"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleNotificationRequest {
    /// PendingNotification TLV.
    #[serde(rename = "pendingNotification")]
    pub pending_notification: Tlv,
}

impl HandleNotificationRequest {
    /// Returns the ES9+ endpoint URL for this request.
    ///
    /// # Arguments
    ///
    /// * `base` - SM-DP+ base URL.
    ///
    /// # Returns
    ///
    /// The HandleNotification URL.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let request = euicc::es9p::HandleNotificationRequest {
    ///     pending_notification: euicc::bertlv::Tlv::constructed(
    ///         euicc::bertlv::Class::Universal.constructed(16),
    ///         Vec::new(),
    ///     )?,
    /// };
    /// let base = url::Url::parse("https://smdp.example")?;
    /// assert!(request.url(&base)?.path().ends_with("/handleNotification"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, HANDLE_NOTIFICATION_PATH)
    }
}

/// ES9+.HandleNotification JSON response.
///
/// # Arguments
///
/// This struct is deserialized from the SM-DP+ response body when present.
///
/// # Returns
///
/// Optional header metadata. The function has no response-specific body fields.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON.
///
/// # Examples
///
/// ```
/// let response = euicc::es9p::HandleNotificationResponse { header: None };
/// assert!(response.execution_status().is_some_and(|status| status.executed_success()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HandleNotificationResponse {
    /// Optional RSP response header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
}

impl HandleNotificationResponse {
    /// Returns `Executed-Success` when the response omits a header.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// The header status or an implicit success for this notification function.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let response = euicc::es9p::HandleNotificationResponse { header: None };
    /// assert!(response.execution_status().is_some_and(|status| status.executed_success()));
    /// ```
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
/// # Arguments
///
/// Build from an ES10b.CancelSession response TLV.
///
/// # Returns
///
/// A serializable CancelSession request body.
///
/// # Errors
///
/// Serialization can fail if nested TLV encoding fails.
///
/// # Examples
///
/// ```
/// let request = euicc::es9p::CancelSessionRequest {
///     transaction_id: euicc::identifier::HexBytes::from_bytes([0x01]),
///     cancel_session_response: euicc::bertlv::Tlv::constructed(
///         euicc::bertlv::Class::ContextSpecific.constructed(65),
///         Vec::new(),
///     )?,
/// };
/// assert!(serde_json::to_string(&request)?.contains("cancelSessionResponse"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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
    /// # Arguments
    ///
    /// * `base` - SM-DP+ base URL.
    ///
    /// # Returns
    ///
    /// The CancelSession URL.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when URL joining fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let request = euicc::es9p::CancelSessionRequest {
    ///     transaction_id: euicc::identifier::HexBytes::default(),
    ///     cancel_session_response: euicc::bertlv::Tlv::constructed(
    ///         euicc::bertlv::Class::ContextSpecific.constructed(65),
    ///         Vec::new(),
    ///     )?,
    /// };
    /// let base = url::Url::parse("https://smdp.example")?;
    /// assert!(request.url(&base)?.path().ends_with("/cancelSession"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn url(&self, base: &Url) -> Result<Url> {
        endpoint(base, CANCEL_SESSION_PATH)
    }
}

/// ES9+.CancelSession JSON response.
///
/// # Arguments
///
/// This struct is deserialized from the SM-DP+ JSON response body.
///
/// # Returns
///
/// Optional header metadata. The function has no response-specific body fields.
///
/// # Errors
///
/// Deserialization can fail for invalid JSON.
///
/// # Examples
///
/// ```
/// let response = euicc::es9p::CancelSessionResponse { header: None };
/// assert!(response.execution_status().is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CancelSessionResponse {
    /// Optional RSP response header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
}

impl CancelSessionResponse {
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
    /// let response = euicc::es9p::CancelSessionResponse { header: None };
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
