//! Profile metadata decoded from ES10c responses.

mod class;
mod icon;
mod info;
mod notification_config;
mod operator;
mod state;
mod tlv;

pub use class::ProfileClass;
pub use icon::{ProfileIcon, ProfileIconType};
pub use info::ProfileInfo;
pub use notification_config::{NotificationConfiguration, NotificationConfigurationInfo};
pub use operator::OperatorId;
pub use state::ProfileState;

#[cfg(test)]
mod tests {
    use crate::bertlv::{Class, Tlv};
    use crate::notification::NotificationEvent;

    use super::*;

    #[test]
    fn profile_info_allows_missing_optional_fields() {
        // Arrange
        let tlv = Tlv::constructed(Class::Private.constructed(3), Vec::new())
            .expect("profile TLV builds");

        // Act
        let profile = ProfileInfo::from_tlv(&tlv).expect("profile decodes");

        // Assert
        assert_eq!(profile.iccid, None);
        assert_eq!(profile.isdp_aid, None);
        assert_eq!(profile.state, Some(ProfileState::Disabled));
        assert_eq!(profile.icon_type, Some(ProfileIconType::Jpg));
        assert_eq!(profile.class, Some(ProfileClass::Provisioning));
        assert_eq!(profile.nickname, None);
        assert_eq!(profile.owner, None);
    }

    #[test]
    fn operator_id_short_plmn_does_not_panic() {
        // Arrange
        let operator = OperatorId {
            plmn: vec![0x13],
            gid1: None,
            gid2: None,
        };

        // Act
        let mcc = operator.mcc();
        let mnc = operator.mnc();

        // Assert
        assert_eq!(mcc, None);
        assert_eq!(mnc, None);
    }

    #[test]
    fn notification_configuration_decodes_spec_sequence_entries() {
        // Arrange
        let entry = Tlv::constructed(
            Class::Universal.constructed(16),
            vec![
                Tlv::primitive(
                    Class::ContextSpecific.primitive(0),
                    NotificationEvent::Install.to_bytes(),
                )
                .expect("operation TLV builds"),
                Tlv::primitive(Class::ContextSpecific.primitive(1), b"smdp.example")
                    .expect("address TLV builds"),
            ],
        )
        .expect("entry TLV builds");
        let tlv = Tlv::constructed(Class::ContextSpecific.constructed(22), vec![entry])
            .expect("configuration TLV builds");

        // Act
        let info = NotificationConfigurationInfo::from_tlv(&tlv).expect("configuration decodes");

        // Assert
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].operations, vec![NotificationEvent::Install]);
        assert_eq!(info.entries[0].address, "smdp.example");
    }

    #[test]
    fn profile_info_decodes_authenticate_client_profile_metadata() {
        // Arrange
        let tlv = Tlv::from_base64(concat!(
            "vyWBjVoKmFgyJCBCSCZpZJEGQ01MSU5LkgdDTUlfR0RTthowGIACBHCBEmNvbnN1",
            "bWVyLnJzcC53b3JsZLcdgANU9CGBCv////////////+CCv////////////+/djLi",
            "MOEiwSA6yVumdHCV8I0+WJoSqtB4vuLOqh4/PnGVvchLJYeB2OMK2wgAAAAAAAAAAQ==",
        ))
        .expect("profile metadata TLV parses");

        // Act
        let profile = ProfileInfo::from_tlv(&tlv).expect("profile decodes");

        // Assert
        assert_eq!(
            profile.iccid.as_ref().map(ToString::to_string),
            Some("89852342022484629646".to_owned())
        );
        assert_eq!(profile.profile_name.as_deref(), Some("CMI_GDS"));
        assert_eq!(profile.service_provider_name.as_deref(), Some("CMLINK"));
        let config = profile
            .notification_configuration
            .as_ref()
            .expect("notification configuration is present");
        assert_eq!(config.entries.len(), 1);
        assert_eq!(
            config.entries[0].operations,
            vec![
                NotificationEvent::Enable,
                NotificationEvent::Disable,
                NotificationEvent::Delete,
            ]
        );
        assert_eq!(config.entries[0].address, "consumer.rsp.world");
    }

    #[test]
    fn profile_info_decodes_go_additional_optional_fields() {
        // Arrange
        let smdp_data = Tlv::constructed(Class::ContextSpecific.constructed(24), Vec::new())
            .expect("SMDP data TLV builds");
        let service_data = Tlv::constructed(Class::ContextSpecific.constructed(34), Vec::new())
            .expect("service data TLV builds");
        let tlv = Tlv::constructed(
            Class::Private.constructed(3),
            vec![
                Tlv::primitive(Class::ContextSpecific.primitive(19), [0x01])
                    .expect("icon type TLV builds"),
                Tlv::primitive(Class::ContextSpecific.primitive(25), [0x05, 0x60])
                    .expect("policy rules TLV builds"),
                smdp_data.clone(),
                service_data.clone(),
            ],
        )
        .expect("profile TLV builds");

        // Act
        let profile = ProfileInfo::from_tlv(&tlv).expect("profile decodes");

        // Assert
        assert_eq!(profile.icon_type, Some(ProfileIconType::Png));
        assert_eq!(profile.profile_policy_rules, Some(vec![false, true, true]));
        assert_eq!(profile.smdp_proprietary_data, Some(smdp_data));
        assert_eq!(profile.service_specific_data, Some(service_data));
    }

    #[test]
    fn operator_id_decodes_context_specific_children() {
        // Arrange
        let tlv = Tlv::constructed(
            Class::ContextSpecific.constructed(23),
            vec![
                Tlv::primitive(Class::ContextSpecific.primitive(0), [0x13, 0xF2, 0x60])
                    .expect("PLMN TLV builds"),
                Tlv::primitive(Class::ContextSpecific.primitive(1), [0xAA])
                    .expect("GID1 TLV builds"),
                Tlv::primitive(Class::ContextSpecific.primitive(2), [0xBB])
                    .expect("GID2 TLV builds"),
            ],
        )
        .expect("operator TLV builds");

        // Act
        let operator = OperatorId::from_tlv(&tlv).expect("operator decodes");

        // Assert
        assert_eq!(operator.plmn, vec![0x13, 0xF2, 0x60]);
        assert_eq!(operator.gid1, Some(vec![0xAA]));
        assert_eq!(operator.gid2, Some(vec![0xBB]));
    }

    #[test]
    fn notification_configuration_rejects_universal_automatic_tags() {
        // Arrange
        let entry = Tlv::constructed(
            Class::Universal.constructed(16),
            vec![
                Tlv::primitive(Class::Universal.primitive(3), [0x04, 0xC0])
                    .expect("operation TLV builds"),
                Tlv::primitive(Class::Universal.primitive(12), b"smdp.example")
                    .expect("address TLV builds"),
            ],
        )
        .expect("entry TLV builds");
        let tlv = Tlv::constructed(Class::ContextSpecific.constructed(22), vec![entry])
            .expect("configuration TLV builds");

        // Act
        let result = NotificationConfigurationInfo::from_tlv(&tlv);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn notification_configuration_rejects_missing_address() {
        // Arrange
        let entry = Tlv::constructed(
            Class::Universal.constructed(16),
            vec![
                Tlv::primitive(
                    Class::ContextSpecific.primitive(0),
                    NotificationEvent::Install.to_bytes(),
                )
                .expect("operation TLV builds"),
            ],
        )
        .expect("entry TLV builds");
        let tlv = Tlv::constructed(Class::ContextSpecific.constructed(22), vec![entry])
            .expect("configuration TLV builds");

        // Act
        let result = NotificationConfigurationInfo::from_tlv(&tlv);

        // Assert
        assert!(matches!(
            result,
            Err(crate::EuiccError::MissingField("notificationAddress"))
        ));
    }
}
