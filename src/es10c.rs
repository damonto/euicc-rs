//! ES10c card functions for profile management.

pub use crate::error::{ProfileOperation, ProfileOperationError, ProfileOperationResult};

use crate::apdu::{CardRequest, CardResponse};
use crate::bertlv::{Class, DecodeTlv, EncodeTlv, Form, Tag, Tlv};
use crate::error::{EuiccError, Result};
use crate::identifier::{Iccid, IsdpAid, ProfileClass};
use crate::primitive::{decode_i64, encode_bit_string, encode_bool, encode_i64};
use crate::profile::ProfileInfo;

/// Profile identifier used by ES10c profile operations.
///
/// # Arguments
///
/// Variants encode either ICCID or ISD-P AID.
///
/// # Returns
///
/// A typed profile identifier.
///
/// # Errors
///
/// Constructing this enum does not return errors.
///
/// # Examples
///
/// ```
/// let id = euicc::es10c::ProfileIdentifier::Iccid(
///     euicc::identifier::Iccid::new("8944478600004573128")?,
/// );
/// assert!(matches!(id, euicc::es10c::ProfileIdentifier::Iccid(_)));
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileIdentifier {
    /// ICCID profile identifier.
    Iccid(Iccid),
    /// ISD-P AID profile identifier.
    IsdpAid(IsdpAid),
}

impl ProfileIdentifier {
    fn to_tlv(&self) -> Result<Tlv> {
        match self {
            Self::Iccid(iccid) => {
                Tlv::primitive(Class::Application.primitive(26), iccid.as_bytes())
            }
            Self::IsdpAid(aid) => Tlv::primitive(Class::Application.primitive(15), aid.as_bytes()),
        }
    }
}

/// Search criterion for ES10c.GetProfilesInfo.
///
/// # Arguments
///
/// Variants encode ICCID, ISD-P AID, or profile class criteria.
///
/// # Returns
///
/// A typed profile search criterion.
///
/// # Errors
///
/// Constructing this enum does not return errors.
///
/// # Examples
///
/// ```
/// let criterion = euicc::es10c::ProfileSearchCriterion::Class(
///     euicc::identifier::ProfileClass::Operational,
/// );
/// assert!(matches!(criterion, euicc::es10c::ProfileSearchCriterion::Class(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileSearchCriterion {
    /// Search by ICCID.
    Iccid(Iccid),
    /// Search by ISD-P AID.
    IsdpAid(IsdpAid),
    /// Search by profile class.
    Class(ProfileClass),
}

impl ProfileSearchCriterion {
    fn to_tlv(&self) -> Result<Tlv> {
        match self {
            Self::Iccid(iccid) => {
                Tlv::primitive(Class::Application.primitive(26), iccid.as_bytes())
            }
            Self::IsdpAid(aid) => Tlv::primitive(Class::Application.primitive(15), aid.as_bytes()),
            Self::Class(class) => {
                let code = match class {
                    ProfileClass::Test => 0,
                    ProfileClass::Provisioning => 1,
                    ProfileClass::Operational => 2,
                    ProfileClass::Unknown(value) => i64::from(*value),
                };
                Tlv::primitive(Class::ContextSpecific.primitive(21), encode_i64(code))
            }
        }
    }
}

/// ES10c.GetProfilesInfo request.
///
/// # Arguments
///
/// Build with optional search criteria and optional tag list.
///
/// # Returns
///
/// A `[45] SEQUENCE` request.
///
/// # Errors
///
/// Encoding returns TLV construction errors if fields are inconsistent.
///
/// # Examples
///
/// ```
/// let request = euicc::es10c::ProfileInfoListRequest {
///     search_criterion: None,
///     tags: Vec::new(),
/// };
/// assert_eq!(request.to_tlv()?.to_bytes()?, vec![0xBF, 0x2D, 0x00]);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileInfoListRequest {
    /// Optional search criterion.
    pub search_criterion: Option<ProfileSearchCriterion>,
    /// Optional tag list. Empty means default profile info.
    pub tags: Vec<Tag>,
}

impl EncodeTlv for ProfileInfoListRequest {
    fn to_tlv(&self) -> Result<Tlv> {
        let mut children = Vec::new();
        if let Some(criteria) = &self.search_criterion {
            children.push(Tlv::constructed(
                Class::ContextSpecific.constructed(0),
                vec![criteria.to_tlv()?],
            )?);
        }
        let tag_list = unique_tag_bytes(&self.tags);
        if !tag_list.is_empty() {
            children.push(Tlv::primitive(Class::Application.primitive(28), tag_list)?);
        }
        constructed(45, children)
    }
}

impl CardRequest for ProfileInfoListRequest {
    type Response = ProfileInfoListResponse;

    fn decode_response(&self, tlv: &Tlv) -> Result<Self::Response> {
        ProfileInfoListResponse::from_tlv(tlv)
    }
}

/// ES10c.GetProfilesInfo response.
///
/// # Arguments
///
/// Use [`ProfileInfoListResponse::from_tlv`] to decode card data.
///
/// # Returns
///
/// A list of profile metadata entries.
///
/// # Errors
///
/// Decoding returns [`EuiccError`] when profile entries or error result fields
/// are malformed.
///
/// # Examples
///
/// ```
/// let tlv = euicc::bertlv::Tlv::constructed(
///     euicc::bertlv::Class::ContextSpecific.constructed(45),
///     Vec::new(),
/// )?;
/// let response = euicc::es10c::ProfileInfoListResponse::from_tlv(&tlv)?;
/// assert!(response.profiles.is_empty());
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileInfoListResponse {
    /// Decoded profiles.
    pub profiles: Vec<ProfileInfo>,
}

impl DecodeTlv for ProfileInfoListResponse {
    fn from_tlv(tlv: &Tlv) -> Result<Self> {
        ensure_tag(tlv, 45, "profileInfoListResponse")?;
        if let Some(error) = tlv.first(&Class::ContextSpecific.primitive(1)) {
            let error = decode_i64(error.value().unwrap_or_default(), 1)?;
            return match error {
                1 => Err(EuiccError::IncorrectInputValues),
                127 => Err(EuiccError::Undefined),
                _ => Err(EuiccError::Undefined),
            };
        }
        let Some(choice) = tlv.first(&Class::ContextSpecific.constructed(0)) else {
            let Some(child) = tlv.children().unwrap_or_default().first() else {
                return Ok(Self::default());
            };
            return Err(EuiccError::UnexpectedTag {
                expected: "profileInfoListOk",
                actual: child.tag().hex(),
            });
        };

        let mut profiles = Vec::new();
        for child in choice.children().unwrap_or_default() {
            if child.tag().is(Class::Private, Form::Constructed, 3) {
                profiles.push(ProfileInfo::from_tlv(child)?);
            }
        }
        Ok(Self { profiles })
    }
}

impl ProfileInfoListResponse {
    /// Decodes the response from a TLV.
    ///
    /// # Arguments
    ///
    /// * `tlv` - `[45]` response TLV.
    ///
    /// # Returns
    ///
    /// Decoded profile list.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the response is malformed or contains an
    /// error result.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(45),
    ///     Vec::new(),
    /// )?;
    /// assert!(euicc::es10c::ProfileInfoListResponse::from_tlv(&tlv)?.profiles.is_empty());
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        <Self as DecodeTlv>::from_tlv(tlv)
    }
}

impl CardResponse for ProfileInfoListResponse {}

/// ES10c profile operation request.
///
/// # Arguments
///
/// Build with operation, identifier, and refresh flag.
///
/// # Returns
///
/// A `[49]`, `[50]`, or `[51]` request.
///
/// # Errors
///
/// Encoding returns TLV construction errors if fields are inconsistent.
///
/// # Examples
///
/// ```
/// let request = euicc::es10c::ProfileOperationRequest {
///     operation: euicc::error::ProfileOperation::Delete,
///     identifier: euicc::es10c::ProfileIdentifier::Iccid(
///         euicc::identifier::Iccid::new("8944478600004573128")?,
///     ),
///     refresh: false,
/// };
/// assert_eq!(request.to_tlv()?.tag().value(), 51);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileOperationRequest {
    /// Operation to execute.
    pub operation: ProfileOperation,
    /// Profile identifier.
    pub identifier: ProfileIdentifier,
    /// Whether REFRESH is required for enable/disable.
    pub refresh: bool,
}

impl EncodeTlv for ProfileOperationRequest {
    fn to_tlv(&self) -> Result<Tlv> {
        let identifier = self.identifier.to_tlv()?;
        let children = if self.operation == ProfileOperation::Delete {
            vec![identifier]
        } else {
            vec![
                Tlv::constructed(Class::ContextSpecific.constructed(0), vec![identifier])?,
                Tlv::primitive(
                    Class::ContextSpecific.primitive(1),
                    encode_bool(self.refresh),
                )?,
            ]
        };
        constructed(self.operation.tag_value(), children)
    }
}

impl CardRequest for ProfileOperationRequest {
    type Response = ProfileOperationResponse;

    fn decode_response(&self, tlv: &Tlv) -> Result<Self::Response> {
        ProfileOperationResponse::from_tlv(self.operation, tlv)
    }
}

/// ES10c profile operation response.
///
/// # Arguments
///
/// Use [`ProfileOperationResponse::from_tlv`] with the operation being decoded.
///
/// # Returns
///
/// The operation and result code.
///
/// # Errors
///
/// Decoding returns [`EuiccError`] when the tag or result field is malformed.
///
/// # Examples
///
/// ```
/// let tlv = euicc::bertlv::Tlv::constructed(
///     euicc::bertlv::Class::ContextSpecific.constructed(49),
///     vec![euicc::bertlv::Tlv::primitive(
///         euicc::bertlv::Class::ContextSpecific.primitive(0),
///         [0x00],
///     )?],
/// )?;
/// let response = euicc::es10c::ProfileOperationResponse::from_tlv(
///     euicc::error::ProfileOperation::Enable,
///     &tlv,
/// )?;
/// response.validate()?;
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ProfileOperationResponse {
    /// Operation represented by this response.
    pub operation: ProfileOperation,
    /// Card result code.
    pub result: ProfileOperationResult,
}

impl ProfileOperationResponse {
    /// Decodes a profile operation response from a TLV.
    ///
    /// # Arguments
    ///
    /// * `operation` - Operation used to determine the expected response tag.
    /// * `tlv` - Response TLV.
    ///
    /// # Returns
    ///
    /// Decoded operation response.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the tag or result field is malformed.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(51),
    ///     vec![euicc::bertlv::Tlv::primitive(
    ///         euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///         [0x00],
    ///     )?],
    /// )?;
    /// assert_eq!(
    ///     euicc::es10c::ProfileOperationResponse::from_tlv(
    ///         euicc::error::ProfileOperation::Delete,
    ///         &tlv,
    ///     )?
    ///     .result,
    ///     euicc::error::ProfileOperationResult::Ok,
    /// );
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_tlv(operation: ProfileOperation, tlv: &Tlv) -> Result<Self> {
        ensure_tag(tlv, operation.tag_value(), "profileOperationResponse")?;
        Ok(Self {
            operation,
            result: ProfileOperationResult::from_i64(required_int(
                tlv,
                Class::ContextSpecific.primitive(0),
                "profileOperationResult",
                1,
            )?),
        })
    }
}

impl CardResponse for ProfileOperationResponse {
    fn validate(&self) -> Result<()> {
        match self.result {
            ProfileOperationResult::Ok => Ok(()),
            ProfileOperationResult::IccidOrAidNotFound
            | ProfileOperationResult::ProfileNotInExpectedState
            | ProfileOperationResult::DisallowedByPolicy
            | ProfileOperationResult::UndefinedError => {
                Err(ProfileOperationError::new(self.operation, self.result).into())
            }
            ProfileOperationResult::WrongProfileReenabling
                if self.operation == ProfileOperation::Enable =>
            {
                Err(ProfileOperationError::new(self.operation, self.result).into())
            }
            ProfileOperationResult::CatBusy
                if self.operation == ProfileOperation::Enable
                    || self.operation == ProfileOperation::Disable =>
            {
                Err(ProfileOperationError::new(self.operation, self.result).into())
            }
            _ => Err(EuiccError::Undefined),
        }
    }
}

/// ES10c.eUICCMemoryReset request.
///
/// # Arguments
///
/// Build from the three reset option booleans.
///
/// # Returns
///
/// A `[52] SEQUENCE` request.
///
/// # Errors
///
/// Encoding does not fail unless TLV construction invariants are violated.
///
/// # Examples
///
/// ```
/// let request = euicc::es10c::EuiccMemoryResetRequest {
///     delete_operational_profiles: true,
///     delete_field_loaded_test_profiles: false,
///     reset_default_smdp_address: false,
/// };
/// assert_eq!(request.to_tlv()?.tag().value(), 52);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct EuiccMemoryResetRequest {
    /// Delete operational profiles.
    pub delete_operational_profiles: bool,
    /// Delete field-loaded test profiles.
    pub delete_field_loaded_test_profiles: bool,
    /// Reset default SM-DP+ address.
    pub reset_default_smdp_address: bool,
}

impl EncodeTlv for EuiccMemoryResetRequest {
    fn to_tlv(&self) -> Result<Tlv> {
        constructed(
            52,
            vec![Tlv::primitive(
                Class::ContextSpecific.primitive(2),
                encode_bit_string(&[
                    self.delete_operational_profiles,
                    self.delete_field_loaded_test_profiles,
                    self.reset_default_smdp_address,
                ]),
            )?],
        )
    }
}

impl CardRequest for EuiccMemoryResetRequest {
    type Response = EuiccMemoryResetResponse;

    fn decode_response(&self, tlv: &Tlv) -> Result<Self::Response> {
        EuiccMemoryResetResponse::from_tlv(tlv)
    }
}

/// Memory reset result code.
///
/// # Arguments
///
/// Values are decoded from the card response integer.
///
/// # Returns
///
/// A typed memory reset result.
///
/// # Errors
///
/// Unknown values are represented by [`Self::Unknown`].
///
/// # Examples
///
/// ```
/// assert_eq!(
///     euicc::es10c::EuiccMemoryResetResult::from_i64(5),
///     euicc::es10c::EuiccMemoryResetResult::CatBusy,
/// );
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EuiccMemoryResetResult {
    /// Operation completed successfully.
    Ok,
    /// Nothing matched the reset options.
    NothingToDelete,
    /// CAT is busy.
    CatBusy,
    /// Undefined card error.
    UndefinedError,
    /// Unknown result.
    Unknown(i8),
}

impl EuiccMemoryResetResult {
    /// Decodes a signed memory reset result code.
    ///
    /// # Arguments
    ///
    /// * `value` - Signed integer result.
    ///
    /// # Returns
    ///
    /// A typed result code.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::es10c::EuiccMemoryResetResult::from_i64(1),
    ///     euicc::es10c::EuiccMemoryResetResult::NothingToDelete,
    /// );
    /// ```
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::NothingToDelete,
            5 => Self::CatBusy,
            127 => Self::UndefinedError,
            other => Self::Unknown(other as i8),
        }
    }
}

/// ES10c.eUICCMemoryReset response.
///
/// # Arguments
///
/// Use [`EuiccMemoryResetResponse::from_tlv`] to decode from card data.
///
/// # Returns
///
/// Memory reset result.
///
/// # Errors
///
/// Decoding returns [`EuiccError`] when the response is malformed.
///
/// # Examples
///
/// ```
/// let tlv = euicc::bertlv::Tlv::constructed(
///     euicc::bertlv::Class::ContextSpecific.constructed(52),
///     vec![euicc::bertlv::Tlv::primitive(
///         euicc::bertlv::Class::ContextSpecific.primitive(0),
///         [0x00],
///     )?],
/// )?;
/// euicc::es10c::EuiccMemoryResetResponse::from_tlv(&tlv)?.validate()?;
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EuiccMemoryResetResponse {
    /// Memory reset result code.
    pub result: EuiccMemoryResetResult,
}

impl DecodeTlv for EuiccMemoryResetResponse {
    fn from_tlv(tlv: &Tlv) -> Result<Self> {
        ensure_tag(tlv, 52, "euiccMemoryResetResponse")?;
        Ok(Self {
            result: EuiccMemoryResetResult::from_i64(required_int(
                tlv,
                Class::ContextSpecific.primitive(0),
                "resetResult",
                1,
            )?),
        })
    }
}

impl EuiccMemoryResetResponse {
    /// Decodes the response from a TLV.
    ///
    /// # Arguments
    ///
    /// * `tlv` - `[52]` response TLV.
    ///
    /// # Returns
    ///
    /// Decoded memory reset response.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the response is malformed.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(52),
    ///     vec![euicc::bertlv::Tlv::primitive(
    ///         euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///         [0x00],
    ///     )?],
    /// )?;
    /// assert_eq!(
    ///     euicc::es10c::EuiccMemoryResetResponse::from_tlv(&tlv)?.result,
    ///     euicc::es10c::EuiccMemoryResetResult::Ok,
    /// );
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        <Self as DecodeTlv>::from_tlv(tlv)
    }
}

impl CardResponse for EuiccMemoryResetResponse {
    fn validate(&self) -> Result<()> {
        match self.result {
            EuiccMemoryResetResult::Ok => Ok(()),
            EuiccMemoryResetResult::NothingToDelete => Err(EuiccError::NothingToDelete),
            EuiccMemoryResetResult::CatBusy => Err(EuiccError::CatBusy),
            EuiccMemoryResetResult::UndefinedError | EuiccMemoryResetResult::Unknown(_) => {
                Err(EuiccError::Undefined)
            }
        }
    }
}

/// ES10c.GetEID request.
///
/// # Arguments
///
/// This zero-sized request has no command parameters.
///
/// # Returns
///
/// A `[62] SEQUENCE` request with tagList set to `5A`.
///
/// # Errors
///
/// Encoding does not fail unless TLV construction invariants are violated.
///
/// # Examples
///
/// ```
/// assert_eq!(euicc::es10c::GetEuiccDataRequest.to_tlv()?.tag().value(), 62);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct GetEuiccDataRequest;

impl EncodeTlv for GetEuiccDataRequest {
    fn to_tlv(&self) -> Result<Tlv> {
        constructed(
            62,
            vec![Tlv::primitive(
                Class::Application.primitive(28),
                Class::Application.primitive(26).as_bytes(),
            )?],
        )
    }
}

impl CardRequest for GetEuiccDataRequest {
    type Response = GetEuiccDataResponse;

    fn decode_response(&self, tlv: &Tlv) -> Result<Self::Response> {
        GetEuiccDataResponse::from_tlv(tlv)
    }
}

/// ES10c.GetEID response.
///
/// # Arguments
///
/// Use [`GetEuiccDataResponse::from_tlv`] to decode from card data.
///
/// # Returns
///
/// Raw EID bytes.
///
/// # Errors
///
/// Decoding returns [`EuiccError::MissingField`] when tag `5A` is absent.
///
/// # Examples
///
/// ```
/// let tlv = euicc::bertlv::Tlv::constructed(
///     euicc::bertlv::Class::ContextSpecific.constructed(62),
///     vec![euicc::bertlv::Tlv::primitive(
///         euicc::bertlv::Class::Application.primitive(26),
///         [0x12; 16],
///     )?],
/// )?;
/// let response = euicc::es10c::GetEuiccDataResponse::from_tlv(&tlv)?;
/// assert_eq!(response.eid.len(), 16);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetEuiccDataResponse {
    /// EID bytes.
    pub eid: Vec<u8>,
}

impl DecodeTlv for GetEuiccDataResponse {
    fn from_tlv(tlv: &Tlv) -> Result<Self> {
        ensure_tag(tlv, 62, "getEuiccDataResponse")?;
        Ok(Self {
            eid: required_value(tlv, Class::Application.primitive(26), "eidValue")?.to_vec(),
        })
    }
}

impl GetEuiccDataResponse {
    /// Decodes the response from a TLV.
    ///
    /// # Arguments
    ///
    /// * `tlv` - `[62]` response TLV.
    ///
    /// # Returns
    ///
    /// Decoded EID response.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the response is malformed.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(62),
    ///     vec![euicc::bertlv::Tlv::primitive(
    ///         euicc::bertlv::Class::Application.primitive(26),
    ///         [0x12; 16],
    ///     )?],
    /// )?;
    /// assert_eq!(euicc::es10c::GetEuiccDataResponse::from_tlv(&tlv)?.eid.len(), 16);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        <Self as DecodeTlv>::from_tlv(tlv)
    }
}

impl CardResponse for GetEuiccDataResponse {}

/// ES10c.SetNickname request.
///
/// # Arguments
///
/// Build from ICCID and nickname text.
///
/// # Returns
///
/// A `[41] SEQUENCE` request.
///
/// # Errors
///
/// Encoding returns [`EuiccError::InvalidText`] when the nickname exceeds
/// 64 UTF-8 bytes.
///
/// # Examples
///
/// ```
/// let request = euicc::es10c::SetNicknameRequest {
///     iccid: euicc::identifier::Iccid::new("8944478600004573128")?,
///     nickname: "work".to_owned(),
/// };
/// assert_eq!(request.to_tlv()?.tag().value(), 41);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetNicknameRequest {
    /// Profile ICCID.
    pub iccid: Iccid,
    /// New profile nickname.
    pub nickname: String,
}

impl SetNicknameRequest {
    /// Validates nickname constraints.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the nickname is at most 64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::InvalidText`] when the nickname is too long.
    ///
    /// # Examples
    ///
    /// ```
    /// let request = euicc::es10c::SetNicknameRequest {
    ///     iccid: euicc::identifier::Iccid::new("8944478600004573128")?,
    ///     nickname: "work".to_owned(),
    /// };
    /// request.validate()?;
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.nickname.len() > 64 {
            return Err(EuiccError::InvalidText("profile nickname too long"));
        }
        Ok(())
    }
}

impl EncodeTlv for SetNicknameRequest {
    fn to_tlv(&self) -> Result<Tlv> {
        self.validate()?;
        constructed(
            41,
            vec![
                Tlv::primitive(Class::Application.primitive(26), self.iccid.as_bytes())?,
                Tlv::primitive(
                    Class::ContextSpecific.primitive(16),
                    self.nickname.as_bytes(),
                )?,
            ],
        )
    }
}

impl CardRequest for SetNicknameRequest {
    type Response = SetNicknameResponse;

    fn decode_response(&self, tlv: &Tlv) -> Result<Self::Response> {
        SetNicknameResponse::from_tlv(tlv)
    }
}

/// SetNickname result code.
///
/// # Arguments
///
/// Values are decoded from the card response integer.
///
/// # Returns
///
/// A typed nickname result.
///
/// # Errors
///
/// Unknown values are represented by [`Self::Unknown`].
///
/// # Examples
///
/// ```
/// assert_eq!(
///     euicc::es10c::SetNicknameResult::from_i64(1),
///     euicc::es10c::SetNicknameResult::IccidNotFound,
/// );
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SetNicknameResult {
    /// Operation completed successfully.
    Ok,
    /// ICCID was not found.
    IccidNotFound,
    /// Undefined card error.
    UndefinedError,
    /// Unknown result.
    Unknown(i8),
}

impl SetNicknameResult {
    /// Decodes a signed nickname result code.
    ///
    /// # Arguments
    ///
    /// * `value` - Signed integer result.
    ///
    /// # Returns
    ///
    /// A typed result code.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::es10c::SetNicknameResult::from_i64(127),
    ///     euicc::es10c::SetNicknameResult::UndefinedError,
    /// );
    /// ```
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::IccidNotFound,
            127 => Self::UndefinedError,
            other => Self::Unknown(other as i8),
        }
    }
}

/// ES10c.SetNickname response.
///
/// # Arguments
///
/// Use [`SetNicknameResponse::from_tlv`] to decode from card data.
///
/// # Returns
///
/// SetNickname result.
///
/// # Errors
///
/// Decoding returns [`EuiccError`] when the response is malformed.
///
/// # Examples
///
/// ```
/// let tlv = euicc::bertlv::Tlv::constructed(
///     euicc::bertlv::Class::ContextSpecific.constructed(41),
///     vec![euicc::bertlv::Tlv::primitive(
///         euicc::bertlv::Class::ContextSpecific.primitive(0),
///         [0x00],
///     )?],
/// )?;
/// euicc::es10c::SetNicknameResponse::from_tlv(&tlv)?.validate()?;
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SetNicknameResponse {
    /// Nickname result code.
    pub result: SetNicknameResult,
}

impl DecodeTlv for SetNicknameResponse {
    fn from_tlv(tlv: &Tlv) -> Result<Self> {
        ensure_tag(tlv, 41, "setNicknameResponse")?;
        Ok(Self {
            result: SetNicknameResult::from_i64(required_int(
                tlv,
                Class::ContextSpecific.primitive(0),
                "setNicknameResult",
                1,
            )?),
        })
    }
}

impl SetNicknameResponse {
    /// Decodes the response from a TLV.
    ///
    /// # Arguments
    ///
    /// * `tlv` - `[41]` response TLV.
    ///
    /// # Returns
    ///
    /// Decoded SetNickname response.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the response is malformed.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(41),
    ///     vec![euicc::bertlv::Tlv::primitive(
    ///         euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///         [0x00],
    ///     )?],
    /// )?;
    /// assert_eq!(
    ///     euicc::es10c::SetNicknameResponse::from_tlv(&tlv)?.result,
    ///     euicc::es10c::SetNicknameResult::Ok,
    /// );
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        <Self as DecodeTlv>::from_tlv(tlv)
    }
}

impl CardResponse for SetNicknameResponse {
    fn validate(&self) -> Result<()> {
        match self.result {
            SetNicknameResult::Ok => Ok(()),
            SetNicknameResult::IccidNotFound => Err(EuiccError::IccidNotFound),
            SetNicknameResult::UndefinedError | SetNicknameResult::Unknown(_) => {
                Err(EuiccError::Undefined)
            }
        }
    }
}

macro_rules! inherent_to_tlv {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl $ty {
                /// Encodes this request as an ES10 BER-TLV object.
                ///
                /// # Arguments
                ///
                /// This method takes no arguments.
                ///
                /// # Returns
                ///
                /// The encoded request TLV.
                ///
                /// # Errors
                ///
                /// Returns protocol validation or TLV construction errors from
                /// the request-specific encoder.
                ///
                /// # Examples
                ///
                /// ```
                /// let tlv = euicc::es10c::GetEuiccDataRequest.to_tlv()?;
                /// assert_eq!(tlv.tag().value(), 62);
                /// # Ok::<(), euicc::EuiccError>(())
                /// ```

                pub fn to_tlv(&self) -> Result<Tlv> {
                    <Self as EncodeTlv>::to_tlv(self)
                }
            }
        )+
    };
}
inherent_to_tlv!(
    ProfileInfoListRequest,
    ProfileOperationRequest,
    EuiccMemoryResetRequest,
    GetEuiccDataRequest,
    SetNicknameRequest,
);

macro_rules! inherent_validate {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl $ty {
                /// Validates the decoded ES10 response.
                ///
                /// # Arguments
                ///
                /// This method takes no arguments.
                ///
                /// # Returns
                ///
                /// `Ok(())` when the response represents success.
                ///
                /// # Errors
                ///
                /// Returns a protocol-specific [`EuiccError`] for card-level
                /// failure result codes.
                ///
                /// # Examples
                ///
                /// ```
                /// let response = euicc::es10c::GetEuiccDataResponse { eid: vec![0; 16] };
                /// response.validate()?;
                /// # Ok::<(), euicc::EuiccError>(())
                /// ```

                pub fn validate(&self) -> Result<()> {
                    <Self as CardResponse>::validate(self)
                }
            }
        )+
    };
}
inherent_validate!(
    ProfileInfoListResponse,
    ProfileOperationResponse,
    EuiccMemoryResetResponse,
    GetEuiccDataResponse,
    SetNicknameResponse,
);

fn constructed(value: u64, children: Vec<Tlv>) -> Result<Tlv> {
    Tlv::constructed(Class::ContextSpecific.constructed(value), children)
}

fn ensure_tag(tlv: &Tlv, value: u64, expected: &'static str) -> Result<()> {
    if !tlv
        .tag()
        .is(Class::ContextSpecific, Form::Constructed, value)
    {
        return Err(EuiccError::UnexpectedTag {
            expected,
            actual: tlv.tag().hex(),
        });
    }
    Ok(())
}

fn required_value<'a>(parent: &'a Tlv, tag: Tag, name: &'static str) -> Result<&'a [u8]> {
    parent
        .first(&tag)
        .and_then(Tlv::value)
        .ok_or(EuiccError::MissingField(name))
}

fn required_int(parent: &Tlv, tag: Tag, name: &'static str, max_bytes: usize) -> Result<i64> {
    decode_i64(required_value(parent, tag, name)?, max_bytes)
}

fn unique_tag_bytes(tags: &[Tag]) -> Vec<u8> {
    let mut seen: Vec<Tag> = Vec::with_capacity(tags.len());
    let mut out = Vec::new();
    for tag in tags {
        if seen.iter().any(|existing| existing == tag) {
            continue;
        }
        seen.push(tag.clone());
        out.extend_from_slice(tag.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_info_list_tag_list_uses_full_tag_deduplication() {
        // Arrange
        let request = ProfileInfoListRequest {
            search_criterion: None,
            tags: vec![
                Class::Application.primitive(26),
                Class::ContextSpecific.primitive(112),
                Class::Application.primitive(26),
            ],
        };

        // Act
        let bytes = request
            .to_tlv()
            .and_then(|tlv| tlv.to_bytes())
            .expect("request encodes");

        // Assert
        assert_eq!(bytes, vec![0xBF, 0x2D, 0x05, 0x5C, 0x03, 0x5A, 0x9F, 0x70]);
    }

    #[test]
    fn set_nickname_rejects_overlong_text() {
        // Arrange
        let request = SetNicknameRequest {
            iccid: Iccid::new("8944478600004573128").expect("ICCID parses"),
            nickname: "a".repeat(65),
        };

        // Act
        let err = request.validate();

        // Assert
        assert!(matches!(err, Err(EuiccError::InvalidText(_))));
    }

    #[test]
    fn profile_info_list_response_decodes_context_specific_choice() {
        // Arrange
        let success = Tlv::from_bytes(&[0xBF, 0x2D, 0x02, 0xA0, 0x00]).expect("success TLV parses");
        let error =
            Tlv::from_bytes(&[0xBF, 0x2D, 0x03, 0x81, 0x01, 0x01]).expect("error TLV parses");

        // Act
        let success = ProfileInfoListResponse::from_tlv(&success).expect("response decodes");
        let error = ProfileInfoListResponse::from_tlv(&error);

        // Assert
        assert!(success.profiles.is_empty());
        assert!(matches!(error, Err(EuiccError::IncorrectInputValues)));
    }

    #[test]
    fn profile_operation_request_wraps_identifier_for_enable_disable() {
        // Arrange
        let request = ProfileOperationRequest {
            operation: ProfileOperation::Enable,
            identifier: ProfileIdentifier::IsdpAid(IsdpAid::from_bytes([0x01])),
            refresh: true,
        };

        // Act
        let bytes = request
            .to_tlv()
            .and_then(|tlv| tlv.to_bytes())
            .expect("request encodes");

        // Assert
        assert_eq!(
            bytes,
            vec![
                0xBF, 0x31, 0x08, 0xA0, 0x03, 0x4F, 0x01, 0x01, 0x81, 0x01, 0xFF
            ]
        );
    }

    #[test]
    fn profile_operation_response_decodes_context_specific_result() {
        // Arrange
        let tlv =
            Tlv::from_bytes(&[0xBF, 0x31, 0x03, 0x80, 0x01, 0x00]).expect("response TLV parses");

        // Act
        let response = ProfileOperationResponse::from_tlv(ProfileOperation::Enable, &tlv)
            .expect("response decodes");

        // Assert
        assert_eq!(response.result, ProfileOperationResult::Ok);
    }

    #[test]
    fn euicc_memory_reset_response_decodes_context_specific_result() {
        // Arrange
        let tlv =
            Tlv::from_bytes(&[0xBF, 0x34, 0x03, 0x80, 0x01, 0x00]).expect("response TLV parses");

        // Act
        let response = EuiccMemoryResetResponse::from_tlv(&tlv).expect("response decodes");

        // Assert
        assert_eq!(response.result, EuiccMemoryResetResult::Ok);
    }

    #[test]
    fn set_nickname_response_decodes_context_specific_result() {
        // Arrange
        let tlv =
            Tlv::from_bytes(&[0xBF, 0x29, 0x03, 0x80, 0x01, 0x00]).expect("response TLV parses");

        // Act
        let response = SetNicknameResponse::from_tlv(&tlv).expect("response decodes");

        // Assert
        assert_eq!(response.result, SetNicknameResult::Ok);
    }
}
