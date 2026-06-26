use std::{borrow::Cow, time::Duration};

use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, HeaderValue, USER_AGENT};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;

use crate::{EuiccError, Result, rootci};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_USER_AGENT: &str = "gsma-rsp-lpad";
const DEFAULT_ADMIN_PROTOCOL_VERSION: &str = "2.5.0";
const ADMIN_PROTOCOL_HEADER: &str = "X-Admin-Protocol";
const JSON_CONTENT_TYPE: &str = "application/json";

/// JSON HTTP transport used by [`Client`].
///
/// # Errors
///
/// Implementors convert network, HTTP-status, serialization, and
/// deserialization failures into [`EuiccError`].
#[async_trait]
pub trait JsonHttpClient: Send + Sync {
    /// Sends one ES9+/ES11 JSON request.
    ///
    /// # Errors
    ///
    /// Returns transport, status, serialization, or deserialization errors.
    ///
    async fn send_json<Request, Response>(&self, url: &Url, request: &Request) -> Result<Response>
    where
        Request: Serialize + Sync,
        Response: DeserializeOwned + Send;
}

/// Default ES9+/ES11 JSON HTTP transport backed by [`reqwest`].
///
/// # Errors
///
/// Request, HTTP status, and JSON decoding failures are converted into
/// [`EuiccError::Http`].
#[derive(Debug, Clone)]
pub struct ReqwestJsonHttpClient {
    client: reqwest::Client,
    admin_protocol_version: Cow<'static, str>,
}

impl ReqwestJsonHttpClient {
    /// Creates a default reqwest-backed JSON HTTP transport.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Http`] when the embedded Root CI bundle cannot be
    /// parsed or reqwest cannot build the client.
    pub fn new() -> Result<Self> {
        let client = Self::client_builder()?
            .build()
            .map_err(|error| EuiccError::Http(format!("build reqwest client: {error}")))?;
        Ok(Self::from_client(client))
    }

    /// Creates a reqwest builder with the crate's default eUICC HTTP settings.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Http`] when an embedded Root CI bundle cannot be
    /// parsed.
    pub fn client_builder() -> Result<reqwest::ClientBuilder> {
        let mut builder = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .user_agent(DEFAULT_USER_AGENT);
        for certificate in rootci::certificates()? {
            builder = builder.add_root_certificate(certificate);
        }
        Ok(builder)
    }

    /// Wraps an already configured reqwest client.
    #[must_use]
    pub fn from_client(client: reqwest::Client) -> Self {
        Self {
            client,
            admin_protocol_version: Cow::Borrowed(DEFAULT_ADMIN_PROTOCOL_VERSION),
        }
    }

    /// Sets the GSMA admin protocol version used in the HTTP header.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::InvalidText`] when the version is empty or not an
    /// SGP.22 `2.x` admin protocol version.
    pub fn with_admin_protocol_version(mut self, version: impl Into<String>) -> Result<Self> {
        self.admin_protocol_version = normalize_admin_protocol_version(version.into())?;
        Ok(self)
    }

    /// Returns the normalized GSMA admin protocol version.
    #[must_use]
    pub fn admin_protocol_version(&self) -> &str {
        &self.admin_protocol_version
    }

    /// Returns the underlying reqwest client.
    #[must_use]
    pub const fn inner(&self) -> &reqwest::Client {
        &self.client
    }

    fn admin_protocol_header(&self) -> Result<HeaderValue> {
        HeaderValue::from_str(&format!("gsma/rsp/v{}", self.admin_protocol_version))
            .map_err(|error| EuiccError::Http(format!("build admin protocol header: {error}")))
    }
}

#[async_trait]
impl JsonHttpClient for ReqwestJsonHttpClient {
    async fn send_json<Request, Response>(&self, url: &Url, request: &Request) -> Result<Response>
    where
        Request: Serialize + Sync,
        Response: DeserializeOwned + Send,
    {
        let admin_protocol = self.admin_protocol_header()?;
        let response = self
            .client
            .post(url.clone())
            .header(CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(USER_AGENT, DEFAULT_USER_AGENT)
            .header(ADMIN_PROTOCOL_HEADER, admin_protocol)
            .json(request)
            .send()
            .await
            .map_err(|error| EuiccError::Http(format!("send JSON request: {error}")))?;
        let response = response
            .error_for_status()
            .map_err(|error| EuiccError::Http(format!("HTTP status: {error}")))?;
        response
            .json::<Response>()
            .await
            .map_err(|error| EuiccError::Http(format!("decode JSON response: {error}")))
    }
}
pub(super) fn normalize_admin_protocol_version(version: String) -> Result<Cow<'static, str>> {
    let trimmed = version.trim();
    let normalized = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if normalized.is_empty() || !normalized.starts_with('2') {
        return Err(EuiccError::InvalidText(
            "unsupported admin protocol version",
        ));
    }
    Ok(Cow::Owned(normalized.to_owned()))
}
