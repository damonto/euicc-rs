//! Notification metadata and search criteria types.

use crate::bertlv::{Class, DecodeTlv, Form, Tlv};
use crate::error::{EuiccError, Result};
use crate::identifier::Iccid;
use crate::primitive::{decode_bit_string, decode_i64, encode_bit_string, encode_i64};

/// Notification sequence number.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SequenceNumber(i64);

impl SequenceNumber {
    /// Creates a sequence number.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Returns the wrapped sequence number.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }

    /// Encodes this sequence number as a BER integer payload.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        encode_i64(self.0)
    }
}

/// Profile management operation represented by notification bit strings.
///
/// # Errors
///
/// Decoding from bits returns [`EuiccError::MalformedTlv`] when no event bit is
/// set.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum NotificationEvent {
    /// Install notification.
    Install,
    /// Enable notification.
    Enable,
    /// Disable notification.
    Disable,
    /// Delete notification.
    Delete,
}

impl NotificationEvent {
    /// Returns this event's bit index.
    #[must_use]
    pub const fn bit_index(self) -> usize {
        match self {
            Self::Install => 0,
            Self::Enable => 1,
            Self::Disable => 2,
            Self::Delete => 3,
        }
    }

    /// Decodes an event from a BER bit-string payload.
    ///
    /// # Errors
    ///
    /// Returns bit-string decoding errors or [`EuiccError::MalformedTlv`] when
    /// no supported event bit is set or multiple bits are set.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let bits = decode_bit_string(data)?;
        let mut event = None;
        for (index, bit) in bits.into_iter().enumerate() {
            if !bit {
                continue;
            }
            let decoded = match index {
                0 => Self::Install,
                1 => Self::Enable,
                2 => Self::Disable,
                3 => Self::Delete,
                _ => return Err(EuiccError::MalformedTlv("notification event")),
            };
            if event.replace(decoded).is_some() {
                return Err(EuiccError::MalformedTlv(
                    "notification event has multiple bits set",
                ));
            }
        }
        event.ok_or(EuiccError::MalformedTlv("notification event is missing"))
    }

    /// Encodes this event as a BER bit-string payload.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bits = [false; 4];
        bits[self.bit_index()] = true;
        encode_bit_string(&bits)
    }
}

/// Notification metadata decoded from ES10b responses.
///
/// # Errors
///
/// Decoding returns [`EuiccError`] when mandatory TLV fields are missing or
/// malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMetadata {
    /// Notification sequence number.
    pub sequence_number: SequenceNumber,
    /// Profile management operation.
    pub operation: NotificationEvent,
    /// RSP server address.
    pub address: String,
    /// ICCID associated with the notification when present.
    pub iccid: Option<Iccid>,
}

impl DecodeTlv for NotificationMetadata {
    fn from_tlv(tlv: &Tlv) -> Result<Self> {
        if !tlv.tag().is(Class::ContextSpecific, Form::Constructed, 47) {
            return Err(EuiccError::UnexpectedTag {
                expected: "notificationMetadata",
                actual: tlv.tag().hex(),
            });
        }
        let sequence = required_value(tlv, Class::ContextSpecific.primitive(0), "seqNumber")?;
        let operation = required_value(
            tlv,
            Class::ContextSpecific.primitive(1),
            "profileManagementOperation",
        )?;
        let address = required_utf8(tlv, Class::Universal.primitive(12), "notificationAddress")?;
        let iccid = tlv
            .first(&Class::Application.primitive(26))
            .and_then(Tlv::value)
            .map(|value| Iccid::from_bytes(value.to_vec()));

        Ok(Self {
            sequence_number: SequenceNumber::new(decode_i64(sequence, 8)?),
            operation: NotificationEvent::from_bytes(operation)?,
            address,
            iccid,
        })
    }
}

impl NotificationMetadata {
    /// Decodes notification metadata from a TLV.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when mandatory fields are missing or malformed.
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        <Self as DecodeTlv>::from_tlv(tlv)
    }
}

/// Pending notification wrapper returned by RetrieveNotificationsList.
///
/// # Errors
///
/// Decoding returns [`EuiccError`] when the pending notification shape is
/// malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingNotification {
    /// Raw pending notification TLV to send to ES9+.HandleNotification.
    pub pending_notification: Tlv,
    /// Decoded metadata.
    pub notification: NotificationMetadata,
}

impl DecodeTlv for PendingNotification {
    fn from_tlv(tlv: &Tlv) -> Result<Self> {
        let is_profile_installation_result =
            tlv.tag().is(Class::ContextSpecific, Form::Constructed, 55);
        let is_other_signed_notification = tlv.tag().is(Class::Universal, Form::Constructed, 16);
        if !is_profile_installation_result && !is_other_signed_notification {
            return Err(EuiccError::UnexpectedTag {
                expected: "pendingNotification",
                actual: tlv.tag().hex(),
            });
        }

        let metadata = if is_profile_installation_result {
            tlv.select(&[
                Class::ContextSpecific.constructed(39),
                Class::ContextSpecific.constructed(47),
            ])
            .ok_or(EuiccError::MissingField("notificationMetadata"))?
        } else {
            tlv.first(&Class::ContextSpecific.constructed(47))
                .ok_or(EuiccError::MissingField("notificationMetadata"))?
        };

        Ok(Self {
            pending_notification: tlv.clone(),
            notification: NotificationMetadata::from_tlv(metadata)?,
        })
    }
}

impl PendingNotification {
    /// Decodes a pending notification from a TLV.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError`] when the wrapper or metadata is malformed.
    pub fn from_tlv(tlv: &Tlv) -> Result<Self> {
        <Self as DecodeTlv>::from_tlv(tlv)
    }
}

fn required_value<'a>(
    parent: &'a Tlv,
    tag: crate::bertlv::Tag,
    name: &'static str,
) -> Result<&'a [u8]> {
    parent
        .first(&tag)
        .and_then(Tlv::value)
        .ok_or(EuiccError::MissingField(name))
}

fn required_utf8(parent: &Tlv, tag: crate::bertlv::Tag, name: &'static str) -> Result<String> {
    let value = required_value(parent, tag, name)?;
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| EuiccError::InvalidText(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bertlv::Tlv;

    #[test]
    fn notification_event_round_trips() {
        // Arrange
        let event = NotificationEvent::Delete;

        // Act
        let encoded = event.to_bytes();
        let decoded = NotificationEvent::from_bytes(&encoded).expect("event decodes");

        // Assert
        assert_eq!(encoded, vec![0x04, 0x10]);
        assert_eq!(decoded, event);
    }

    #[test]
    fn notification_event_rejects_multiple_bits() {
        // Arrange
        let encoded = [0x04, 0xC0];

        // Act
        let result = NotificationEvent::from_bytes(&encoded);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn notification_event_rejects_empty_bits() {
        // Arrange
        let encoded = [0x04, 0x00];

        // Act
        let result = NotificationEvent::from_bytes(&encoded);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn notification_metadata_decodes_optional_fields() {
        // Arrange
        let tlv = Tlv::constructed(
            Class::ContextSpecific.constructed(47),
            vec![
                Tlv::primitive(Class::ContextSpecific.primitive(0), [0x01])
                    .expect("sequence TLV builds"),
                Tlv::primitive(
                    Class::ContextSpecific.primitive(1),
                    NotificationEvent::Install.to_bytes(),
                )
                .expect("event TLV builds"),
                Tlv::primitive(Class::Universal.primitive(12), b"smdp.example")
                    .expect("address TLV builds"),
            ],
        )
        .expect("metadata TLV builds");

        // Act
        let metadata = NotificationMetadata::from_tlv(&tlv).expect("metadata decodes");

        // Assert
        assert_eq!(metadata.sequence_number, SequenceNumber::new(1));
        assert_eq!(metadata.operation, NotificationEvent::Install);
        assert_eq!(metadata.address, "smdp.example");
        assert_eq!(metadata.iccid, None);
    }

    #[test]
    fn notification_metadata_rejects_context_specific_address() {
        // Arrange
        let tlv = Tlv::constructed(
            Class::ContextSpecific.constructed(47),
            vec![
                Tlv::primitive(Class::ContextSpecific.primitive(0), [0x01])
                    .expect("sequence TLV builds"),
                Tlv::primitive(
                    Class::ContextSpecific.primitive(1),
                    NotificationEvent::Install.to_bytes(),
                )
                .expect("event TLV builds"),
                Tlv::primitive(Class::ContextSpecific.primitive(2), b"smdp.example")
                    .expect("address TLV builds"),
            ],
        )
        .expect("metadata TLV builds");

        // Act
        let result = NotificationMetadata::from_tlv(&tlv);

        // Assert
        assert!(result.is_err());
    }
}
