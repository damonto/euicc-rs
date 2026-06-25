use std::fmt;

use serde::{Deserialize, Serialize};

/// Remote RSP status-code data.
///
/// # Arguments
///
/// This struct is deserialized from `statusCodeData`.
///
/// # Returns
///
/// Subject code, reason code, and optional human-readable message.
///
/// # Errors
///
/// Serialization and deserialization errors are returned by `serde`.
///
/// # Examples
///
/// ```
/// let data = euicc::rsp::StatusCodeData {
///     subject_code: "8.1".to_owned(),
///     reason_code: "4.8".to_owned(),
///     message: None,
/// };
/// assert!(data.to_string().contains("sufficient space"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StatusCodeData {
    /// RSP subject code.
    #[serde(
        rename = "subjectCode",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub subject_code: String,
    /// RSP reason code.
    #[serde(
        rename = "reasonCode",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub reason_code: String,
    /// Optional server-supplied message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl StatusCodeData {
    /// Returns the best available message for this status code.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// The server message, a known SGP.22 mapping, or a fallback code string.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let data = euicc::rsp::StatusCodeData {
    ///     subject_code: "8.1".to_owned(),
    ///     reason_code: "4.8".to_owned(),
    ///     message: None,
    /// };
    /// assert!(data.message_text().contains("Profile"));
    /// ```
    #[must_use]
    pub fn message_text(&self) -> String {
        if let Some(message) = &self.message
            && !message.is_empty()
        {
            return message.clone();
        }
        for (subject, reason, message) in RSP_ERRORS {
            if self.subject_code == *subject && self.reason_code == *reason {
                return (*message).to_owned();
            }
        }
        format!(
            "SubjectCode: {}, ReasonCode: {}",
            self.subject_code, self.reason_code
        )
    }
}

impl fmt::Display for StatusCodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message_text())
    }
}

impl std::error::Error for StatusCodeData {}

const RSP_ERRORS: &[(&str, &str, &str)] = &[
    (
        "8.1",
        "4.8",
        "eUICC does not have sufficient space for this Profile",
    ),
    (
        "8.1",
        "6.1",
        "eUICC signature is invalid or serverChallenge is invalid",
    ),
    (
        "8.1.1",
        "2.2",
        "Indicates that the EID is missing in the context of this order (SM-DS address provided or MatchingID value is empty)",
    ),
    (
        "8.1.1",
        "3.1",
        "Indicates that a different EID is already associated with this ICCID",
    ),
    ("8.1.1", "3.8", "EID doesn't match the expected value"),
    (
        "8.1.1",
        "3.10",
        "Indicates that a different EID is already associated with this ICCID",
    ),
    ("8.1.2", "6.1", "EUM Certificate is invalid"),
    ("8.1.2", "6.3", "EUM Certificate has expired"),
    ("8.1.3", "6.1", "eUICC Certificate is invalid"),
    ("8.1.3", "6.3", "eUICC Certificate has expired"),
    ("8.2", "1.2", "Profile has not yet been released"),
    ("8.2", "3.7", "BPP is not available for a new binding"),
    (
        "8.2.1",
        "1.2",
        "Indicates that the function caller is not allowed to perform this function on the target Profile",
    ),
    (
        "8.2.1",
        "3.3",
        "Indicates that the Profile identified by the provided ICCID is not available",
    ),
    (
        "8.2.1",
        "3.5",
        "Indicates that the target Profile cannot be released",
    ),
    (
        "8.2.1",
        "3.9",
        "Indicates that the Profile, identified by this ICCID is unknown to the SM-DP+",
    ),
    (
        "8.2.1",
        "3.10",
        "Indicates that a different EID is associated with this ICCID",
    ),
    (
        "8.2.5",
        "1.2",
        "Indicates that the function caller is not allowed to perform this function on the Profile Type",
    ),
    (
        "8.2.5",
        "3.7",
        "No more Profile available for the requested Profile Type",
    ),
    (
        "8.2.5",
        "3.8",
        "Indicates that the Profile Type identified by this Profile Type is not aligned with the Profile Type of Profile identified by the ICCID",
    ),
    (
        "8.2.5",
        "3.9",
        "Indicates that the Profile Type identified by this Profile Type is unknown to the SM-DP+",
    ),
    ("8.2.5", "4.3", "No eligible Profile for this eUICC/Device"),
    ("8.2.6", "3.3", "Conflicting MatchingID value"),
    (
        "8.2.6",
        "3.8",
        "MatchingID (AC_Token or EventID) is refused",
    ),
    (
        "8.2.6",
        "3.10",
        "Indicates that a different MatchingID is associated with this ICCID",
    ),
    ("8.2.7", "2.2", "Confirmation Code is missing"),
    ("8.2.7", "3.8", "Confirmation Code is refused"),
    (
        "8.2.7",
        "6.4",
        "The maximum number of retries for the Confirmation Code has been exceeded",
    ),
    ("8.8", "3.10", "The provided SM-DP+ OID is invalid"),
    ("8.8.1", "3.8", "Invalid SM-DP+ Address"),
    (
        "8.8.2",
        "3.1",
        "None of the proposed Public Key Identifiers is supported by the SM-DP+",
    ),
    (
        "8.8.3",
        "3.1",
        "The Specification Version Number indicated by the eUICC is not supported by the SM-DP+",
    ),
    (
        "8.8.4",
        "3.7",
        "The SM-DP+ has no CERT.DPauth.ECDSA signed by one of the CI Public Key supported by the eUICC",
    ),
    ("8.8.5", "4.10", "The Download order has expired"),
    (
        "8.8.5",
        "6.4",
        "The maximum number of retries for the Profile download order has been exceeded",
    ),
    (
        "8.9",
        "4.2",
        "The cascade SM-DS registration has failed. SMDS has raised an error",
    ),
    (
        "8.9",
        "5.1",
        "Indicates that the smdsAddress is invalid or not reachable.",
    ),
    ("8.9.1", "3.8", "Invalid SM-DS Address"),
    (
        "8.9.2",
        "3.1",
        "None of the proposed Public Key Identifiers is supported by the SM-DS",
    ),
    (
        "8.9.3",
        "3.1",
        "The Specification Version Number indicated by the eUICC is not supported by the SM-DS",
    ),
    (
        "8.9.4",
        "3.7",
        "The SM-DS has no CERT.DS.ECDSA signed by one of the GSMA CI Public Key supported by the eUICC",
    ),
    (
        "8.9.5",
        "3.3",
        "The Event Record already exist in the SM-DS (EventID duplicated)",
    ),
    (
        "8.9.5",
        "3.9",
        "No Event identified by the Event ID for the EID exists",
    ),
    (
        "8.10.1",
        "3.9",
        "The RSP session identified by the TransactionID is unknown",
    ),
    (
        "8.11.1",
        "3.9",
        "Unknown CI Public Key. The CI used by the EUM Certificate is not a trusted root.",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_code_data_uses_known_message() {
        // Arrange
        let data = StatusCodeData {
            subject_code: "8.1".to_owned(),
            reason_code: "4.8".to_owned(),
            message: None,
        };

        // Act
        let message = data.message_text();

        // Assert
        assert_eq!(
            message,
            "eUICC does not have sufficient space for this Profile"
        );
    }

    #[test]
    fn explicit_message_wins() {
        // Arrange
        let data = StatusCodeData {
            subject_code: "8.1".to_owned(),
            reason_code: "4.8".to_owned(),
            message: Some("custom".to_owned()),
        };

        // Act
        let message = data.message_text();

        // Assert
        assert_eq!(message, "custom");
    }
}
