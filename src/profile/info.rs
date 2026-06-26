use crate::bertlv::{Class, DecodeTlv, Form, Tlv};
use crate::error::{EuiccError, Result};
use crate::identifier::{Iccid, IsdpAid, ProfileClass};
use crate::primitive::decode_bit_string;

use super::icon::{ProfileIcon, ProfileIconType};
use super::notification_config::NotificationConfigurationInfo;
use super::operator::OperatorId;
use super::state::ProfileState;
use super::tlv::{optional_int, optional_string, optional_value};

/// Profile metadata entry.
///
/// # Errors
///
/// Decoding returns [`EuiccError`] when the profile-info tag or typed fields are
/// malformed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileInfo {
    /// ICCID when present.
    pub iccid: Option<Iccid>,
    /// ISD-P AID when present.
    pub isdp_aid: Option<IsdpAid>,
    /// Profile state when present.
    pub state: Option<ProfileState>,
    /// Profile nickname when present.
    pub nickname: Option<String>,
    /// Service provider name when present.
    pub service_provider_name: Option<String>,
    /// Profile display name when present.
    pub profile_name: Option<String>,
    /// Profile icon type. Missing card field defaults to JPG.
    pub icon_type: Option<ProfileIconType>,
    /// Profile icon when present.
    pub icon: Option<ProfileIcon>,
    /// Profile class when present.
    pub class: Option<ProfileClass>,
    /// Profile owner when present.
    pub owner: Option<OperatorId>,
    /// Notification configuration when present.
    pub notification_configuration: Option<NotificationConfigurationInfo>,
    /// SM-DP+ proprietary data when present.
    pub smdp_proprietary_data: Option<Tlv>,
    /// Profile policy rules bit string when present.
    pub profile_policy_rules: Option<Vec<bool>>,
    /// Service-specific data when present.
    pub service_specific_data: Option<Tlv>,
}

impl DecodeTlv for ProfileInfo {
    fn from_tlv(tlv: &Tlv) -> Result<Self> {
        let is_profile_info = tlv.tag().is(Class::Private, Form::Constructed, 3)
            || tlv.tag().is(Class::ContextSpecific, Form::Constructed, 37);
        if !is_profile_info {
            return Err(EuiccError::UnexpectedTag {
                expected: "profileInfo",
                actual: tlv.tag().hex(),
            });
        }

        let notification_configuration = tlv
            .first(&Class::ContextSpecific.constructed(22))
            .map(NotificationConfigurationInfo::from_tlv)
            .transpose()?;
        let owner = tlv
            .first(&Class::ContextSpecific.constructed(23))
            .map(OperatorId::from_tlv)
            .transpose()?;

        Ok(Self {
            iccid: optional_value(tlv, Class::Application.primitive(26))
                .map(|value| Iccid::from_bytes(value.to_vec())),
            isdp_aid: optional_value(tlv, Class::Application.primitive(15))
                .map(|value| IsdpAid::from_bytes(value.to_vec())),
            state: Some(
                optional_int(tlv, Class::ContextSpecific.primitive(112), 1)?
                    .map_or(ProfileState::Disabled, ProfileState::from_i64),
            ),
            nickname: optional_string(tlv, Class::ContextSpecific.primitive(16)),
            service_provider_name: optional_string(tlv, Class::ContextSpecific.primitive(17)),
            profile_name: optional_string(tlv, Class::ContextSpecific.primitive(18)),
            icon_type: Some(
                optional_int(tlv, Class::ContextSpecific.primitive(19), 1)?
                    .map_or(ProfileIconType::Jpg, ProfileIconType::from_i64),
            ),
            icon: optional_value(tlv, Class::ContextSpecific.primitive(20))
                .map(|value| ProfileIcon::from_bytes(value.to_vec())),
            class: Some(
                optional_int(tlv, Class::ContextSpecific.primitive(21), 1)?
                    .map_or(ProfileClass::Provisioning, ProfileClass::from_i64),
            ),
            owner,
            notification_configuration,
            smdp_proprietary_data: tlv.first(&Class::ContextSpecific.constructed(24)).cloned(),
            profile_policy_rules: optional_value(tlv, Class::ContextSpecific.primitive(25))
                .map(decode_bit_string)
                .transpose()?,
            service_specific_data: tlv.first(&Class::ContextSpecific.constructed(34)).cloned(),
        })
    }
}

impl ProfileInfo {
    /// Decodes profile metadata from a TLV.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the tag or typed child fields are malformed.
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        <Self as DecodeTlv>::from_tlv(tlv)
    }
}
