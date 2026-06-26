use crate::bertlv::{Class, Form, Tlv};
use crate::error::{EuiccError, Result};
use crate::notification::NotificationEvent;
use crate::primitive::decode_bit_string;

use super::tlv::{required_utf8, required_value};

/// Notification configuration entry.
///
/// # Errors
///
/// Decoding errors are returned by [`NotificationConfigurationInfo::from_tlv`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationConfiguration {
    /// Notification operation.
    pub operation: NotificationEvent,
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
            let operation = notification_event_from_config_bits(required_value(
                child,
                Class::Universal.primitive(3),
                "profileManagementOperation",
            )?)?;
            let address =
                required_utf8(child, Class::Universal.primitive(12), "notificationAddress")?;
            entries.push(NotificationConfiguration { operation, address });
        }
        Ok(Self { entries })
    }
}
fn notification_event_from_config_bits(data: &[u8]) -> Result<NotificationEvent> {
    for (index, bit) in decode_bit_string(data)?.into_iter().enumerate() {
        if !bit {
            continue;
        }
        return match index {
            0 => Ok(NotificationEvent::Install),
            1 => Ok(NotificationEvent::Enable),
            2 => Ok(NotificationEvent::Disable),
            3 => Ok(NotificationEvent::Delete),
            _ => Err(EuiccError::MalformedTlv(
                "notification configuration operation",
            )),
        };
    }
    Err(EuiccError::MalformedTlv(
        "notification configuration operation is missing",
    ))
}
