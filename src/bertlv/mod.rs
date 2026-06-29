//! BER-TLV encoding and decoding primitives.

mod length;
mod octet_string;
pub mod primitive;
mod tag;
mod tlv;
mod traits;

pub use length::{decode_length, encode_length};
pub use octet_string::OctetString;
pub use tag::{Class, Form, Tag};
pub use tlv::{Tlv, TlvBody};
pub use traits::{DecodeTlv, EncodeTlv};

pub(crate) const MAX_LENGTH: usize = 0xFF_FF_FF;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EuiccError;

    #[test]
    fn tag_creation_uses_minimal_high_tag_number_form() {
        // Arrange
        let fixtures = [
            (0x00, vec![0xA0]),
            (0x1E, vec![0xBE]),
            (0x1F, vec![0xBF, 0x1F]),
            (0x7F, vec![0xBF, 0x7F]),
            (0x80, vec![0xBF, 0x81, 0x00]),
        ];

        for (value, expected) in fixtures {
            // Act
            let tag = Tag::new(Class::ContextSpecific, Form::Constructed, value);

            // Assert
            assert_eq!(tag.as_bytes(), expected);
            assert_eq!(tag.value(), value);
        }
    }

    #[test]
    fn length_round_trips_minimal_definite_forms() {
        // Arrange
        let fixtures = [
            (0x00, vec![0x00]),
            (0x7F, vec![0x7F]),
            (0x80, vec![0x81, 0x80]),
            (0xFF, vec![0x81, 0xFF]),
            (0x100, vec![0x82, 0x01, 0x00]),
            (0xFFFF, vec![0x82, 0xFF, 0xFF]),
            (0x10000, vec![0x83, 0x01, 0x00, 0x00]),
        ];

        for (length, expected) in fixtures {
            // Act
            let encoded = encode_length(length).expect("fixture length encodes");
            let decoded = decode_length(&encoded).expect("fixture length decodes");

            // Assert
            assert_eq!(encoded, expected);
            assert_eq!(decoded, (length, expected.len()));
        }
    }

    #[test]
    fn tlv_binary_and_json_round_trip() {
        // Arrange
        let tlv = Tlv::primitive(Class::ContextSpecific.primitive(0), [0xFF])
            .expect("fixture TLV builds");

        // Act
        let binary = tlv.to_bytes().expect("fixture TLV encodes");
        let text = serde_json::to_string(&tlv).expect("fixture TLV serializes");
        let decoded = Tlv::from_bytes(&binary).expect("fixture TLV decodes");
        let decoded_json: Tlv = serde_json::from_str(&text).expect("fixture TLV deserializes");

        // Assert
        assert_eq!(binary, vec![0x80, 0x01, 0xFF]);
        assert_eq!(text, "\"gAH/\"");
        assert_eq!(decoded, tlv);
        assert_eq!(decoded_json, tlv);
    }

    #[test]
    fn constructed_tlv_encodes_children() {
        // Arrange
        let child =
            Tlv::primitive(Class::Universal.primitive(0), [0xFF]).expect("child TLV builds");
        let parent = Tlv::constructed(Class::ContextSpecific.constructed(0), vec![child])
            .expect("parent TLV builds");

        // Act
        let binary = parent.to_bytes().expect("parent TLV encodes");

        // Assert
        assert_eq!(binary, vec![0xA0, 0x03, 0x00, 0x01, 0xFF]);
    }

    #[test]
    fn unpadded_base64_decodes() {
        // Arrange
        let text = "gAL/7g";

        // Act
        let tlv = Tlv::from_base64(text).expect("unpadded TLV decodes");

        // Assert
        assert_eq!(tlv.tag(), &Class::ContextSpecific.primitive(0));
        assert_eq!(tlv.value(), Some(&[0xFF, 0xEE][..]));
    }

    #[test]
    fn tag_parser_rejects_non_minimal_high_tag_number_form() {
        // Arrange
        let short_tag_in_high_form = [0xBF, 0x1E];
        let zero_first_value_octet = [0xBF, 0x80, 0x1F];

        // Act
        let short_tag_error = Tag::from_prefix(&short_tag_in_high_form);
        let zero_octet_error = Tag::from_prefix(&zero_first_value_octet);

        // Assert
        assert!(matches!(short_tag_error, Err(EuiccError::TagEncoding(_))));
        assert!(matches!(zero_octet_error, Err(EuiccError::TagEncoding(_))));
    }

    #[test]
    fn length_parser_rejects_non_minimal_long_form() {
        // Arrange
        let short_length_in_long_form = [0x81, 0x7F];
        let one_byte_length_in_two_bytes = [0x82, 0x00, 0x80];

        // Act
        let short_error = decode_length(&short_length_in_long_form);
        let two_byte_error = decode_length(&one_byte_length_in_two_bytes);

        // Assert
        assert!(matches!(short_error, Err(EuiccError::LengthEncoding(_))));
        assert!(matches!(two_byte_error, Err(EuiccError::LengthEncoding(_))));
    }
}
