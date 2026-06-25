use serde::{Deserialize, Serialize};

use super::ExecutionStatus;

/// Remote function execution header.
///
/// # Arguments
///
/// This struct is deserialized from RSP JSON response headers.
///
/// # Returns
///
/// Header metadata containing execution status and optional function ids.
///
/// # Errors
///
/// Serialization and deserialization errors are returned by `serde`.
///
/// # Examples
///
/// ```
/// let header = euicc::rsp::Header {
///     execution_status: Some(euicc::rsp::ExecutionStatus::success()),
///     requester_id: None,
///     call_id: None,
/// };
/// assert!(header.execution_status().is_some_and(|s| s.executed_success()));
/// ```
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
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Optional borrowed execution status.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let header = euicc::rsp::Header {
    ///     execution_status: Some(euicc::rsp::ExecutionStatus::success()),
    ///     requester_id: None,
    ///     call_id: None,
    /// };
    /// assert!(header.execution_status().is_some());
    /// ```
    #[must_use]
    pub fn execution_status(&self) -> Option<&ExecutionStatus> {
        self.execution_status.as_ref()
    }
}
