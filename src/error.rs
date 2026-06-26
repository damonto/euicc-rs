//! Error and status-code types shared by SGP.22 protocol layers.

use std::fmt;

use thiserror::Error;

use crate::identifier::HexBytes;
use crate::rsp::StatusCodeData;

/// Crate-wide result type whose error side is always [`EuiccError`].
pub type Result<T> = std::result::Result<T, EuiccError>;

/// Errors returned by BER-TLV, RSP, and card-facing helpers.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EuiccError {
    /// A BER-TLV tag did not match the structure expected by the caller.
    #[error("unexpected tag: expected {expected}, got {actual}")]
    UnexpectedTag {
        /// Human-readable expected tag or branch name.
        expected: &'static str,
        /// Actual tag bytes encoded as uppercase hexadecimal.
        actual: String,
    },
    /// A mandatory child TLV or JSON field is absent.
    #[error("missing field {0}")]
    MissingField(&'static str),
    /// A BER-TLV object is malformed for its protocol role.
    #[error("malformed TLV: {0}")]
    MalformedTlv(&'static str),
    /// A BER-TLV tag encoding is incomplete or invalid.
    #[error("tag encoding: {0}")]
    TagEncoding(String),
    /// A BER-TLV length encoding is incomplete or invalid.
    #[error("length encoding: {0}")]
    LengthEncoding(String),
    /// The TLV length exceeds the three-byte limit used by SGP.22 payloads.
    #[error("TLV length {got} exceeds maximum {max}")]
    LengthTooLarge {
        /// Largest supported content length.
        max: usize,
        /// Actual content length.
        got: usize,
    },
    /// A constructed TLV was used where a primitive value is required.
    #[error("primitive value expected")]
    PrimitiveExpected,
    /// A primitive TLV was used where child TLVs are required.
    #[error("constructed value expected")]
    ConstructedExpected,
    /// A signed integer does not fit the target protocol type.
    #[error("integer value is too large: expected at most {max} bytes, got {got}")]
    IntegerTooLarge {
        /// Maximum accepted byte width.
        max: usize,
        /// Actual byte width.
        got: usize,
    },
    /// A BER bit string has invalid padding metadata.
    #[error("invalid bit-string padding")]
    InvalidBitStringPadding,
    /// A BCD identifier contains a non-hexadecimal character.
    #[error("invalid BCD identifier")]
    InvalidBcdIdentifier,
    /// A text field that must be UTF-8 is invalid or too long.
    #[error("{0}")]
    InvalidText(&'static str),
    /// A profile-info search request uses invalid inputs.
    #[error("incorrect input values")]
    IncorrectInputValues,
    /// The requested notification or profile operation had nothing to remove.
    #[error("nothing to delete")]
    NothingToDelete,
    /// The requested ICCID is not known by the card.
    #[error("iccid not found")]
    IccidNotFound,
    /// The card reports CAT busy.
    #[error("cat busy")]
    CatBusy,
    /// The card returned an unspecified error code.
    #[error("undefined error")]
    Undefined,
    /// A profile operation returned a non-success result.
    #[error(transparent)]
    ProfileOperation(#[from] ProfileOperationError),
    /// Loading a bound profile package returned a non-success result.
    #[error(transparent)]
    LoadBoundProfilePackage(#[from] LoadBoundProfilePackageError),
    /// Authenticating the server returned an authenticateResponseError branch.
    #[error(transparent)]
    Authenticate(#[from] AuthenticateResponseError),
    /// A remote RSP server reported a failed execution status.
    #[error(transparent)]
    RspStatus(#[from] StatusCodeData),
    /// Base64 text could not be decoded.
    #[error("decode base64: {0}")]
    Base64(String),
    /// Hexadecimal text could not be decoded.
    #[error("decode hex: {0}")]
    Hex(String),
    /// URL construction failed.
    #[error("build URL: {0}")]
    Url(String),
    /// JSON HTTP transport returned an error.
    #[error("HTTP transport: {0}")]
    Http(String),
    /// Profile download was canceled before installation.
    #[error("profile download canceled")]
    Canceled,
    /// The underlying APDU layer returned an error.
    #[error(transparent)]
    Apdu(#[from] uicc::apdu::ApduError),
}

/// Profile operation kind used by ES10c profile operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProfileOperation {
    /// ES10c.EnableProfile.
    Enable,
    /// ES10c.DisableProfile.
    Disable,
    /// ES10c.DeleteProfile.
    Delete,
}

impl ProfileOperation {
    /// Returns the context-specific tag number for this operation.
    #[must_use]
    pub const fn tag_value(self) -> u64 {
        match self {
            Self::Enable => 49,
            Self::Disable => 50,
            Self::Delete => 51,
        }
    }

    /// Returns the operation name used in card error strings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enable => "enableProfile",
            Self::Disable => "disableProfile",
            Self::Delete => "deleteProfile",
        }
    }
}

impl fmt::Display for ProfileOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result code returned by ES10c profile operations.
///
/// # Errors
///
/// Unknown numeric values are represented by [`Self::Unknown`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProfileOperationResult {
    /// Operation completed successfully.
    Ok,
    /// ICCID or AID was not found.
    IccidOrAidNotFound,
    /// Enable target is not disabled or disable target is not enabled.
    ProfileNotInExpectedState,
    /// Policy rules disallow the operation.
    DisallowedByPolicy,
    /// The card rejects reenabling the same profile.
    WrongProfileReenabling,
    /// CAT is busy.
    CatBusy,
    /// Undefined error.
    UndefinedError,
    /// Unknown card result.
    Unknown(i8),
}

impl ProfileOperationResult {
    /// Decodes a signed integer result code.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::IccidOrAidNotFound,
            2 => Self::ProfileNotInExpectedState,
            3 => Self::DisallowedByPolicy,
            4 => Self::WrongProfileReenabling,
            5 => Self::CatBusy,
            127 => Self::UndefinedError,
            other => Self::Unknown(other as i8),
        }
    }

    fn name(self, operation: ProfileOperation) -> String {
        match self {
            Self::Ok => "ok".to_owned(),
            Self::IccidOrAidNotFound => "iccidOrAidNotFound".to_owned(),
            Self::ProfileNotInExpectedState if operation == ProfileOperation::Disable => {
                "profileNotInEnabledState".to_owned()
            }
            Self::ProfileNotInExpectedState => "profileNotInDisabledState".to_owned(),
            Self::DisallowedByPolicy => "disallowedByPolicy".to_owned(),
            Self::WrongProfileReenabling => "wrongProfileReenabling".to_owned(),
            Self::CatBusy => "catBusy".to_owned(),
            Self::UndefinedError => "undefinedError".to_owned(),
            Self::Unknown(value) => format!("unknown({value})"),
        }
    }
}

/// Error returned by ES10c profile operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{operation},{result_name}")]
pub struct ProfileOperationError {
    /// Operation that returned the error.
    pub operation: ProfileOperation,
    /// Result code returned by the card.
    pub result: ProfileOperationResult,
    result_name: String,
}

impl ProfileOperationError {
    /// Creates a profile operation error.
    #[must_use]
    pub fn new(operation: ProfileOperation, result: ProfileOperationResult) -> Self {
        Self {
            operation,
            result,
            result_name: result.name(operation),
        }
    }

    /// Returns the operation-specific result label.
    #[must_use]
    pub fn result_name(&self) -> &str {
        &self.result_name
    }
}

/// Bound profile package command identifier.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BppCommandId {
    /// initialiseSecureChannel.
    InitialiseSecureChannel,
    /// configureISDP.
    ConfigureIsdp,
    /// storeMetadata.
    StoreMetadata,
    /// storeMetadata2.
    StoreMetadata2,
    /// replaceSessionKeys.
    ReplaceSessionKeys,
    /// loadProfileElements.
    LoadProfileElements,
    /// Unknown command id.
    Unknown(i8),
}

impl BppCommandId {
    /// Decodes a signed integer command id.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::InitialiseSecureChannel,
            1 => Self::ConfigureIsdp,
            2 => Self::StoreMetadata,
            3 => Self::StoreMetadata2,
            4 => Self::ReplaceSessionKeys,
            5 => Self::LoadProfileElements,
            other => Self::Unknown(other as i8),
        }
    }

    /// Returns the SGP.22 command label.
    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            Self::InitialiseSecureChannel => "initialiseSecureChannel".to_owned(),
            Self::ConfigureIsdp => "configureISDP".to_owned(),
            Self::StoreMetadata => "storeMetadata".to_owned(),
            Self::StoreMetadata2 => "storeMetadata2".to_owned(),
            Self::ReplaceSessionKeys => "replaceSessionKeys".to_owned(),
            Self::LoadProfileElements => "loadProfileElements".to_owned(),
            Self::Unknown(value) => format!("unknown({value})"),
        }
    }
}

/// Bound profile package load error reason.
///
/// # Errors
///
/// Unknown numeric values are represented by [`Self::Unknown`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BppErrorReason {
    /// incorrectInputValues.
    IncorrectInputValues,
    /// invalidSignature.
    InvalidSignature,
    /// invalidTransactionId.
    InvalidTransactionId,
    /// unsupportedCrtValues.
    UnsupportedCrtValues,
    /// unsupportedRemoteOperationType.
    UnsupportedRemoteOperationType,
    /// unsupportedProfileClass.
    UnsupportedProfileClass,
    /// scp03tStructureError.
    Scp03tStructureError,
    /// scp03tSecurityError.
    Scp03tSecurityError,
    /// installFailedDueToIccidAlreadyExistsOnEuicc.
    IccidAlreadyExists,
    /// installFailedDueToInsufficientMemoryForProfile.
    InsufficientMemory,
    /// installFailedDueToInterruption.
    Interruption,
    /// installFailedDueToPEProcessingError.
    PeProcessingError,
    /// installFailedDueToDataMismatch.
    DataMismatch,
    /// testProfileInstallFailedDueToInvalidNaaKey.
    InvalidNaaKey,
    /// pprNotAllowed.
    PprNotAllowed,
    /// installFailedDueToUnknownError.
    UnknownInstallError,
    /// Unknown reason code.
    Unknown(i8),
}

impl BppErrorReason {
    /// Decodes a signed integer reason code.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            1 => Self::IncorrectInputValues,
            2 => Self::InvalidSignature,
            3 => Self::InvalidTransactionId,
            4 => Self::UnsupportedCrtValues,
            5 => Self::UnsupportedRemoteOperationType,
            6 => Self::UnsupportedProfileClass,
            7 => Self::Scp03tStructureError,
            8 => Self::Scp03tSecurityError,
            9 => Self::IccidAlreadyExists,
            10 => Self::InsufficientMemory,
            11 => Self::Interruption,
            12 => Self::PeProcessingError,
            13 => Self::DataMismatch,
            14 => Self::InvalidNaaKey,
            15 => Self::PprNotAllowed,
            127 => Self::UnknownInstallError,
            other => Self::Unknown(other as i8),
        }
    }

    /// Returns the SGP.22 reason label.
    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            Self::IncorrectInputValues => "incorrectInputValues".to_owned(),
            Self::InvalidSignature => "invalidSignature".to_owned(),
            Self::InvalidTransactionId => "invalidTransactionId".to_owned(),
            Self::UnsupportedCrtValues => "unsupportedCrtValues".to_owned(),
            Self::UnsupportedRemoteOperationType => "unsupportedRemoteOperationType".to_owned(),
            Self::UnsupportedProfileClass => "unsupportedProfileClass".to_owned(),
            Self::Scp03tStructureError => "scp03tStructureError".to_owned(),
            Self::Scp03tSecurityError => "scp03tSecurityError".to_owned(),
            Self::IccidAlreadyExists => "installFailedDueToIccidAlreadyExistsOnEuicc".to_owned(),
            Self::InsufficientMemory => "installFailedDueToInsufficientMemoryForProfile".to_owned(),
            Self::Interruption => "installFailedDueToInterruption".to_owned(),
            Self::PeProcessingError => "installFailedDueToPEProcessingError".to_owned(),
            Self::DataMismatch => "installFailedDueToDataMismatch".to_owned(),
            Self::InvalidNaaKey => "testProfileInstallFailedDueToInvalidNaaKey".to_owned(),
            Self::PprNotAllowed => "pprNotAllowed".to_owned(),
            Self::UnknownInstallError => "installFailedDueToUnknownError".to_owned(),
            Self::Unknown(value) => format!("unknown({value})"),
        }
    }
}

/// Error returned by ES10b.LoadBoundProfilePackage.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{command_name},{reason_name}")]
pub struct LoadBoundProfilePackageError {
    /// Command id that failed.
    pub command_id: BppCommandId,
    /// Error reason returned by the card.
    pub reason: BppErrorReason,
    command_name: String,
    reason_name: String,
}

impl LoadBoundProfilePackageError {
    /// Creates a load-bound-profile-package error.
    #[must_use]
    pub fn new(command_id: BppCommandId, reason: BppErrorReason) -> Self {
        Self {
            command_id,
            reason,
            command_name: command_id.as_str(),
            reason_name: reason.as_str(),
        }
    }

    /// Returns the command label.
    #[must_use]
    pub fn command_name(&self) -> &str {
        &self.command_name
    }

    /// Returns the reason label.
    #[must_use]
    pub fn reason_name(&self) -> &str {
        &self.reason_name
    }
}

/// AuthenticateServer error code.
///
/// # Errors
///
/// Unknown numeric values are represented by [`Self::Unknown`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthenticateErrorCode {
    /// invalidCertificate.
    InvalidCertificate,
    /// invalidSignature.
    InvalidSignature,
    /// unsupportedCurve.
    UnsupportedCurve,
    /// noSessionContext.
    NoSessionContext,
    /// invalidOid.
    InvalidOid,
    /// euiccChallengeMismatch.
    EuiccChallengeMismatch,
    /// ciPKUnknown.
    CipkUnknown,
    /// undefinedError.
    UndefinedError,
    /// Unknown authenticate error code.
    Unknown(i8),
}

impl AuthenticateErrorCode {
    /// Decodes a signed integer authenticate error code.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            1 => Self::InvalidCertificate,
            2 => Self::InvalidSignature,
            3 => Self::UnsupportedCurve,
            4 => Self::NoSessionContext,
            5 => Self::InvalidOid,
            6 => Self::EuiccChallengeMismatch,
            7 => Self::CipkUnknown,
            127 => Self::UndefinedError,
            other => Self::Unknown(other as i8),
        }
    }

    /// Returns the SGP.22 authenticate error label.
    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            Self::InvalidCertificate => "invalidCertificate".to_owned(),
            Self::InvalidSignature => "invalidSignature".to_owned(),
            Self::UnsupportedCurve => "unsupportedCurve".to_owned(),
            Self::NoSessionContext => "noSessionContext".to_owned(),
            Self::InvalidOid => "invalidOid".to_owned(),
            Self::EuiccChallengeMismatch => "euiccChallengeMismatch".to_owned(),
            Self::CipkUnknown => "ciPKUnknown".to_owned(),
            Self::UndefinedError => "undefinedError".to_owned(),
            Self::Unknown(value) => format!("unknown({value})"),
        }
    }
}

/// Error branch returned by ES10b.AuthenticateServer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("authenticateServer,{code_name}")]
pub struct AuthenticateResponseError {
    /// Transaction id returned by the card.
    pub transaction_id: HexBytes,
    /// Authentication error code.
    pub code: AuthenticateErrorCode,
    code_name: String,
}

impl AuthenticateResponseError {
    /// Creates an authenticate response error.
    #[must_use]
    pub fn new(transaction_id: HexBytes, code: AuthenticateErrorCode) -> Self {
        Self {
            transaction_id,
            code,
            code_name: code.as_str(),
        }
    }

    /// Returns the authenticate error label.
    #[must_use]
    pub fn code_name(&self) -> &str {
        &self.code_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_bound_profile_package_error_names_match_go() {
        // Arrange
        let err = LoadBoundProfilePackageError::new(
            BppCommandId::LoadProfileElements,
            BppErrorReason::PprNotAllowed,
        );

        // Act
        let message = err.to_string();

        // Assert
        assert_eq!(err.command_name(), "loadProfileElements");
        assert_eq!(err.reason_name(), "pprNotAllowed");
        assert_eq!(message, "loadProfileElements,pprNotAllowed");
    }

    #[test]
    fn unknown_bpp_command_is_preserved() {
        // Arrange
        let err = LoadBoundProfilePackageError::new(
            BppCommandId::from_i64(99),
            BppErrorReason::PprNotAllowed,
        );

        // Act
        let command = err.command_name();

        // Assert
        assert_eq!(command, "unknown(99)");
        assert_eq!(err.to_string(), "unknown(99),pprNotAllowed");
    }
}
