use std::borrow::Cow;

use url::Url;

use crate::{EuiccError, Result};

pub(super) fn parse_server_url(address: &str) -> Result<Url> {
    let address = normalize_server_address(address);
    let text = if address.contains("://") {
        Cow::Borrowed(address.as_ref())
    } else {
        Cow::Owned(format!("https://{address}"))
    };
    Url::parse(&text).map_err(|err| EuiccError::Url(err.to_string()))
}

fn normalize_server_address(address: &str) -> Cow<'_, str> {
    let trimmed = address.trim();
    if trimmed.contains(' ') {
        return Cow::Owned(trimmed.replace(' ', ""));
    }
    Cow::Borrowed(trimmed)
}

pub(super) fn server_authority(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or(EuiccError::Url("server URL host is missing".to_owned()))?;
    if let Some(port) = url.port() {
        return Ok(format!("{host}:{port}"));
    }
    Ok(host.to_owned())
}
