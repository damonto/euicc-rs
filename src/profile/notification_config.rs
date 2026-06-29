use crate::bertlv::primitive::decode_bit_string;
use crate::bertlv::{Class, Form, Tlv};
use crate::error::{EuiccError, Result};
use crate::notification::NotificationEvent;

use super::tlv::{required_utf8, required_value};

/// Notification configuration entry.
///
/// # Errors
///
/// Decoding errors are returned by [`NotificationConfigurationInfo::from_tlv`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationConfiguration {
    /// Profile-management operations sharing the same notification address.
    pub operations: Vec<NotificationEvent>,
    /// Destination address.
    pub address: String,
}

/// Notification configuration list.
///
/// # Errors
///
/// Decoding returns [`EuiccError`] when the tag or event bit string is malformed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NotificationConfigurationInfo {
    /// Notification configuration entries.
    pub entries: Vec<NotificationConfiguration>,
}

impl NotificationConfigurationInfo {
    /// Decodes notification configuration info from a TLV.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the tag or operation bit string is malformed.
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        if !tlv.tag().is(Class::ContextSpecific, Form::Constructed, 22) {
            return Err(EuiccError::UnexpectedTag {
                expected: "notificationConfigurationInfo",
                actual: tlv.tag().hex(),
            });
        }
        let children = tlv.children().unwrap_or_default();
        let mut entries = Vec::with_capacity(children.len());
        for child in children {
            if !child.tag().is(Class::Universal, Form::Constructed, 16) {
                return Err(EuiccError::UnexpectedTag {
                    expected: "notificationConfiguration",
                    actual: child.tag().hex(),
                });
            }
            let operations = notification_events_from_config_bits(required_value(
                child,
                Class::ContextSpecific.primitive(0),
                "profileManagementOperation",
            )?)?;
            let address = required_utf8(
                child,
                Class::ContextSpecific.primitive(1),
                "notificationAddress",
            )?;
            entries.push(NotificationConfiguration {
                operations,
                address,
            });
        }
        Ok(Self { entries })
    }
}
fn notification_events_from_config_bits(data: &[u8]) -> Result<Vec<NotificationEvent>> {
    let bits = decode_bit_string(data)?;
    let mut events = Vec::with_capacity(bits.len().min(4));
    for (index, bit) in bits.into_iter().enumerate() {
        if !bit {
            continue;
        }
        let event = match index {
            0 => NotificationEvent::Install,
            1 => NotificationEvent::Enable,
            2 => NotificationEvent::Disable,
            3 => NotificationEvent::Delete,
            _ => Err(EuiccError::MalformedTlv(
                "notification configuration operation",
            ))?,
        };
        events.push(event);
    }
    if events.is_empty() {
        return Err(EuiccError::MalformedTlv(
            "notification configuration operation is missing",
        ));
    }
    Ok(events)
}
