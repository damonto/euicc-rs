use serde::{Deserialize, Serialize};

use super::StatusCodeData;

/// Remote function execution status.
///
/// # Arguments
///
/// This struct is deserialized from RSP JSON status objects.
///
/// # Returns
///
/// A status string plus optional status-code data.
///
/// # Errors
///
/// Serialization and deserialization errors are returned by `serde`.
///
/// # Examples
///
/// ```
/// assert!(euicc::rsp::ExecutionStatus::success().executed_success());
/// ```
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
    ///
    /// # Arguments
    ///
    /// This function takes no arguments.
    ///
    /// # Returns
    ///
    /// An execution status equivalent to a successful RSP response.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::rsp::ExecutionStatus::success().status,
    ///     "Executed-Success",
    /// );
    /// ```
    #[must_use]
    pub fn success() -> Self {
        Self {
            status: "Executed-Success".to_owned(),
            status_code_data: None,
        }
    }

    /// Returns true for `Executed-Success`.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `true` when the status is `Executed-Success`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(euicc::rsp::ExecutionStatus::success().executed_success());
    /// ```
    #[must_use]
    pub fn executed_success(&self) -> bool {
        self.status == "Executed-Success"
    }

    /// Returns true for `Executed-WithWarning`.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `true` when the status is `Executed-WithWarning`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let status = euicc::rsp::ExecutionStatus {
    ///     status: "Executed-WithWarning".to_owned(),
    ///     status_code_data: None,
    /// };
    /// assert!(status.executed_with_warning());
    /// ```
    #[must_use]
    pub fn executed_with_warning(&self) -> bool {
        self.status == "Executed-WithWarning"
    }

    /// Returns true for `Failed`.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `true` when the status is `Failed`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let status = euicc::rsp::ExecutionStatus {
    ///     status: "Failed".to_owned(),
    ///     status_code_data: None,
    /// };
    /// assert!(status.failed());
    /// ```
    #[must_use]
    pub fn failed(&self) -> bool {
        self.status == "Failed"
    }

    /// Returns true for `Expired`.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `true` when the status is `Expired`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let status = euicc::rsp::ExecutionStatus {
    ///     status: "Expired".to_owned(),
    ///     status_code_data: None,
    /// };
    /// assert!(status.expired());
    /// ```
    #[must_use]
    pub fn expired(&self) -> bool {
        self.status == "Expired"
    }
}
