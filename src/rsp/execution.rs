use serde::{Deserialize, Serialize};

use super::StatusCodeData;

/// Remote function execution status.
///
/// # Errors
///
/// Serialization and deserialization errors are returned by `serde`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExecutionStatus {
    /// Status string such as `Executed-Success`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    /// Optional status-code details.
    #[serde(
        rename = "statusCodeData",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub status_code_data: Option<StatusCodeData>,
}

impl ExecutionStatus {
    /// Builds an `Executed-Success` status.
    #[must_use]
    pub fn success() -> Self {
        Self {
            status: "Executed-Success".to_owned(),
            status_code_data: None,
        }
    }

    /// Returns true for `Executed-Success`.
    #[must_use]
    pub fn executed_success(&self) -> bool {
        self.status == "Executed-Success"
    }

    /// Returns true for `Executed-WithWarning`.
    #[must_use]
    pub fn executed_with_warning(&self) -> bool {
        self.status == "Executed-WithWarning"
    }

    /// Returns true for `Failed`.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.status == "Failed"
    }

    /// Returns true for `Expired`.
    #[must_use]
    pub fn expired(&self) -> bool {
        self.status == "Expired"
    }
}
