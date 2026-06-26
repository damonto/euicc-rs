use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use uicc::apdu::ApduTransmitter;

use crate::error::{EuiccError, Result};

use super::GSMA_ISD_R_AID;
use super::transport::{apdu_transport_error, validate_logical_channel};

/// ISD-R logical channel opened through a `uicc-rs` QMI UIM reader.
///
/// # Errors
///
/// Opening the channel returns QCOM transport, slot-activation, or UIM errors.
#[derive(Debug)]
pub struct QcomIsdrChannel<T>
where
    T: uicc::qcom::Transport,
{
    reader: uicc::qcom::uim::Reader<T>,
    channel: uicc::qcom::uim::LogicalChannel,
    logical_channel: u8,
    closed: AtomicBool,
}

impl<T> QcomIsdrChannel<T>
where
    T: uicc::qcom::Transport,
{
    /// Activates the configured slot and opens the default GSMA ISD-R AID.
    ///
    /// # Errors
    ///
    /// Returns QCOM transport, slot-activation, logical-channel, or UIM card
    /// errors.
    pub async fn open(reader: uicc::qcom::uim::Reader<T>) -> Result<Self> {
        Self::open_with_aid(reader, &GSMA_ISD_R_AID).await
    }

    /// Activates the configured slot and opens an explicit ISD-R AID.
    ///
    /// # Errors
    ///
    /// Returns QCOM transport, slot-activation, logical-channel, or UIM card
    /// errors.
    pub async fn open_with_aid(reader: uicc::qcom::uim::Reader<T>, aid: &[u8]) -> Result<Self> {
        reader
            .activate_slot()
            .await
            .map_err(|err| EuiccError::Apdu(apdu_transport_error("QCOM", err)))?;
        let channel = reader
            .open_logical_channel(aid)
            .await
            .map_err(|err| EuiccError::Apdu(apdu_transport_error("QCOM", err)))?;
        let logical_channel = channel.get();
        validate_logical_channel(logical_channel)?;
        Ok(Self {
            reader,
            channel,
            logical_channel,
            closed: AtomicBool::new(false),
        })
    }

    /// Returns the logical channel selected for ISD-R.
    #[must_use]
    pub const fn logical_channel(&self) -> u8 {
        self.logical_channel
    }
}

#[async_trait]
impl<T> ApduTransmitter for QcomIsdrChannel<T>
where
    T: uicc::qcom::Transport,
{
    async fn transmit(&self, request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
        self.reader
            .send_apdu(self.channel, request)
            .await
            .map_err(|err| apdu_transport_error("QCOM", err))
    }

    async fn close(&self) -> uicc::apdu::Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.reader
                .close_logical_channel(self.channel)
                .await
                .map_err(|err| apdu_transport_error("QCOM", err))?;
        }
        self.reader
            .close()
            .await
            .map_err(|err| apdu_transport_error("QCOM", err))
    }
}
