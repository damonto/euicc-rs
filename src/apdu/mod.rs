//! APDU transport adapter for ES10 card commands.

mod card;
mod client;
mod isdr;
mod mbim;
mod qcom;
mod transport;

pub use card::{CardRequest, CardResponse};
pub use client::EuiccApdu;
pub use isdr::IsdrChannel;
pub use mbim::MbimIsdrChannel;
pub use qcom::QcomIsdrChannel;

const TERMINAL_CAPABILITY_APDU: [u8; 15] = [
    0x80, 0xAA, 0x00, 0x00, 0x0A, 0xA9, 0x08, 0x81, 0x00, 0x82, 0x01, 0x01, 0x83, 0x01, 0x07,
];
const MAX_LOGICAL_CHANNEL: u8 = 19;
const MAX_SHORT_APDU_DATA_LENGTH: usize = 255;

/// GSMA SGP.02 ISD-R application identifier used by LPAd ES10 commands.
pub const GSMA_ISD_R_AID: [u8; 16] = [
    0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00,
];

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::mbim::{mbim_apdu_response, mbim_logical_channel};
    use super::*;
    use crate::error::EuiccError;
    use uicc::apdu::{ApduTransmitter, StatusWord};

    #[derive(Debug)]
    struct Script {
        steps: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    }

    #[async_trait]
    impl ApduTransmitter for Script {
        async fn transmit(&self, request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
            let mut steps = self.steps.lock().expect("script lock poisoned");
            let (expected, response) = steps.remove(0);
            assert_eq!(request, expected.as_slice());
            Ok(response)
        }

        async fn close(&self) -> uicc::apdu::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn transmit_raw_segments_store_data_and_reads_response() {
        // Arrange
        let tx = Script {
            steps: Mutex::new(vec![
                (
                    vec![0x80, 0xE2, 0x11, 0x00, 0x02, 0xAA, 0xBB, 0x00],
                    vec![0x90, 0x00],
                ),
                (
                    vec![0x80, 0xE2, 0x91, 0x01, 0x01, 0xCC, 0x00],
                    vec![0x61, 0x03],
                ),
                (
                    vec![0x80, 0xC0, 0x00, 0x00, 0x03],
                    vec![0xDE, 0xAD, 0xBE, 0x90, 0x00],
                ),
            ]),
        };
        let adapter = EuiccApdu::new(tx, 2).expect("adapter builds");

        // Act
        let response = adapter.transmit_raw(&[0xAA, 0xBB, 0xCC]).await;

        // Assert
        assert_eq!(response.expect("raw APDU succeeds"), vec![0xDE, 0xAD, 0xBE]);
    }

    #[tokio::test]
    async fn open_selects_default_isdr_aid_and_close_releases_channel() {
        // Arrange
        let mut select_isdr = vec![0x40, 0xA4, 0x04, 0x00, GSMA_ISD_R_AID.len() as u8];
        select_isdr.extend_from_slice(&GSMA_ISD_R_AID);
        let tx = Script {
            steps: Mutex::new(vec![
                (TERMINAL_CAPABILITY_APDU.to_vec(), vec![0x90, 0x00]),
                (vec![0x00, 0x70, 0x00, 0x00, 0x01], vec![0x04, 0x90, 0x00]),
                (select_isdr, vec![0x90, 0x00]),
                (vec![0x00, 0x70, 0x80, 0x04, 0x00], vec![0x90, 0x00]),
            ]),
        };

        // Act
        let adapter = EuiccApdu::open(tx, 254).await.expect("ISD-R adapter opens");

        // Assert
        assert_eq!(adapter.logical_channel(), Some(4));
        adapter.close().await.expect("ISD-R channel closes");
    }

    #[tokio::test]
    async fn open_closes_logical_channel_when_select_fails() {
        // Arrange
        let tx = Script {
            steps: Mutex::new(vec![
                (TERMINAL_CAPABILITY_APDU.to_vec(), vec![0x90, 0x00]),
                (vec![0x00, 0x70, 0x00, 0x00, 0x01], vec![0x02, 0x90, 0x00]),
                (vec![0x02, 0xA4, 0x04, 0x00, 0x01, 0xA0], vec![0x6A, 0x82]),
                (vec![0x00, 0x70, 0x80, 0x02, 0x00], vec![0x90, 0x00]),
            ]),
        };

        // Act
        let err = IsdrChannel::open_with_aid(tx, &[0xA0]).await;

        // Assert
        assert!(matches!(
            err,
            Err(EuiccError::Apdu(uicc::apdu::ApduError::Status(StatusWord(
                0x6A82
            ))))
        ));
    }

    #[test]
    fn mbim_apdu_response_appends_swapped_status_word() {
        // Arrange
        let response = vec![0xDE, 0xAD];

        // Act
        let response = mbim_apdu_response(response, 0x0090);

        // Assert
        assert_eq!(response, vec![0xDE, 0xAD, 0x90, 0x00]);
    }

    #[test]
    fn mbim_apdu_response_maps_zero_status_to_ok() {
        // Arrange
        let response = vec![0xCA, 0xFE];

        // Act
        let response = mbim_apdu_response(response, 0);

        // Assert
        assert_eq!(response, vec![0xCA, 0xFE, 0x90, 0x00]);
    }

    #[test]
    fn mbim_logical_channel_rejects_out_of_range_values() {
        // Arrange and Act
        let zero = mbim_logical_channel(0);
        let too_high = mbim_logical_channel(u32::from(MAX_LOGICAL_CHANNEL) + 1);

        // Assert
        assert!(zero.is_err());
        assert!(too_high.is_err());
    }
}
