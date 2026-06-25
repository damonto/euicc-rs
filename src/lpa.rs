//! Local Profile Assistant orchestration over ES10 APDU and ES9+/ES11 JSON.

mod activation;
mod client;
mod download;
mod http;
mod server;
mod status;

pub use activation::ActivationCode;
pub use client::Client;
pub use download::{DownloadOptions, DownloadStage};
pub use http::{JsonHttpClient, ReqwestJsonHttpClient};

#[cfg(test)]
mod tests {
    use crate::bertlv::{Class, Tlv};
    use crate::identifier::HexBytes;
    use crate::{EuiccError, es9p};

    use super::ActivationCode;
    use super::http::normalize_admin_protocol_version;
    use super::server::{parse_server_url, server_authority};
    use super::status::check_rsp_status;

    #[test]
    fn activation_code_parses_matching_id_and_serializes() {
        // Arrange and Act
        let code =
            ActivationCode::from_text("LPA:1$smdp.example$abc").expect("activation code parses");

        // Assert
        assert_eq!(code.smdp.as_str(), "https://smdp.example/");
        assert_eq!(code.matching_id.as_deref(), Some("abc"));
        assert_eq!(
            code.to_text().expect("activation code serializes"),
            "LPA:1$smdp.example$abc"
        );
    }

    #[test]
    fn activation_code_preserves_empty_matching_id_before_oid() {
        // Arrange and Act
        let code = ActivationCode::from_text("LPA:1$smdp.example$$1.2.3$1")
            .expect("activation code parses");

        // Assert
        assert_eq!(code.matching_id, None);
        assert_eq!(code.oid.as_deref(), Some("1.2.3"));
        assert!(code.confirmation_code_required);
        assert_eq!(
            code.to_text().expect("activation code serializes"),
            "LPA:1$smdp.example$$1.2.3$1"
        );
    }

    #[test]
    fn server_authority_includes_explicit_port() {
        // Arrange
        let url = url::Url::parse("https://smdp.example:8443/path").expect("URL parses");

        // Act
        let authority = server_authority(&url).expect("authority builds");

        // Assert
        assert_eq!(authority, "smdp.example:8443");
    }

    #[test]
    fn parse_server_url_removes_host_spaces() {
        // Arrange and Act
        let url = parse_server_url("smdp. example").expect("URL parses");

        // Assert
        assert_eq!(url.as_str(), "https://smdp.example/");
    }

    #[test]
    fn admin_protocol_version_strips_v_prefix() {
        // Arrange and Act
        let version =
            normalize_admin_protocol_version("v2.5.0".to_owned()).expect("version normalizes");

        // Assert
        assert_eq!(version, "2.5.0");
    }

    #[test]
    fn admin_protocol_version_rejects_unsupported_major_version() {
        // Arrange and Act
        let result = normalize_admin_protocol_version("3.0.0".to_owned());

        // Assert
        assert!(matches!(result, Err(EuiccError::InvalidText(_))));
    }

    #[test]
    fn authenticate_client_missing_status_maps_to_rsp_status() {
        // Arrange
        let empty_sequence = Tlv::constructed(Class::Universal.constructed(16), Vec::new())
            .expect("sequence TLV builds");
        let response = es9p::AuthenticateClientResponse {
            header: None,
            transaction_id: HexBytes::default(),
            profile_metadata: None,
            smdp_signed2: empty_sequence.clone(),
            smdp_signature2: Tlv::primitive(Class::Application.primitive(55), [])
                .expect("signature TLV builds"),
            smdp_certificate: empty_sequence,
        };

        // Act
        let result = check_rsp_status(&response);

        // Assert
        let Err(EuiccError::RspStatus(status)) = result else {
            panic!("expected RSP status error");
        };
        assert_eq!(
            status.message.as_deref(),
            Some("missing function execution status")
        );
    }

    #[test]
    fn handle_notification_missing_status_is_success() {
        // Arrange
        let response = es9p::HandleNotificationResponse { header: None };

        // Act
        let result = check_rsp_status(&response);

        // Assert
        assert!(result.is_ok());
    }
}
