use std::fmt;

use url::Url;

use crate::{EuiccError, Result};

use super::server::{parse_server_url, server_authority};

/// SGP.22 activation code for profile download.
///
/// # Errors
///
/// Parsing returns [`EuiccError`] for malformed activation code text or URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationCode {
    /// SM-DP+ base URL.
    pub smdp: Url,
    /// Optional MatchingId.
    pub matching_id: Option<String>,
    /// Optional SM-DP+ OID.
    pub oid: Option<String>,
    /// Whether the activation code declares a required confirmation code.
    pub confirmation_code_required: bool,
}

impl ActivationCode {
    /// Creates an activation code from typed parts.
    #[must_use]
    pub const fn new(smdp: Url) -> Self {
        Self {
            smdp,
            matching_id: None,
            oid: None,
            confirmation_code_required: false,
        }
    }

    /// Parses an activation code string.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::InvalidText`] for malformed input or
    /// [`EuiccError::Url`] for invalid SM-DP+ addresses.
    ///
    /// # Examples
    ///
    /// ```
    /// let code = euicc::lpa::ActivationCode::from_text("LPA:1$example.com$match")?;
    /// assert_eq!(code.matching_id.as_deref(), Some("match"));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_text(text: &str) -> Result<Self> {
        if !text.starts_with("LPA:1") {
            return Err(EuiccError::InvalidText("activation code prefix"));
        }
        let parts = text.split('$').collect::<Vec<_>>();
        if parts.len() < 2 || parts[1].is_empty() {
            return Err(EuiccError::InvalidText("activation code smdp address"));
        }
        let smdp = parse_server_url(parts[1])?;
        let matching_id = non_empty_part(parts.get(2).copied());
        let oid = non_empty_part(parts.get(3).copied());
        let confirmation_code_required = parts.get(4).is_some_and(|value| *value == "1");
        Ok(Self {
            smdp,
            matching_id,
            oid,
            confirmation_code_required,
        })
    }

    /// Serializes this activation code as `LPA:1$...` text.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Url`] when the SM-DP+ URL has no host.
    pub fn to_text(&self) -> Result<String> {
        let mut out = format!("LPA:1${}", server_authority(&self.smdp)?);
        if let Some(matching_id) = &self.matching_id {
            out.push('$');
            out.push_str(matching_id);
        }
        if let Some(oid) = &self.oid {
            if self.matching_id.is_none() {
                out.push('$');
            }
            out.push('$');
            out.push_str(oid);
        }
        if self.confirmation_code_required {
            if self.oid.is_none() {
                out.push('$');
            }
            out.push_str("$1");
        }
        Ok(out)
    }
}

impl fmt::Display for ActivationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_text() {
            Ok(text) => formatter.write_str(&text),
            Err(_) => formatter.write_str("LPA:1$"),
        }
    }
}
fn non_empty_part(part: Option<&str>) -> Option<String> {
    part.filter(|value| !value.is_empty()).map(str::to_owned)
}
