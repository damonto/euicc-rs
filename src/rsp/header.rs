use serde::{Deserialize, Serialize};

use super::ExecutionStatus;

/// Remote function execution header.
///
/// # Errors
///
/// Serialization and deserialization errors are returned by `serde`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Header {
    /// Function execution status.
    #[serde(
        rename = "functionExecutionStatus",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub execution_status: Option<ExecutionStatus>,
    /// Function requester identifier.
    #[serde(
        rename = "functionRequesterIdentifier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub requester_id: Option<String>,
    /// Function call identifier.
    #[serde(
        rename = "functionCallIdentifier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub call_id: Option<String>,
}

impl Header {
    /// Returns the execution status.
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.execution_status.as_ref()
    }
}
