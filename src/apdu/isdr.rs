use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use uicc::apdu::{ApduRequest, ApduResponse, ApduTransmitter, StatusWord};

use crate::error::{EuiccError, Result};

use super::{
    GSMA_ISD_R_AID, MAX_LOGICAL_CHANNEL, MAX_SHORT_APDU_DATA_LENGTH, TERMINAL_CAPABILITY_APDU,
};

/// ISD-R logical channel opened over a `uicc` APDU transmitter.
///
/// # Errors
///
/// Opening the channel returns APDU transport or status-word errors.
#[derive(Debug)]
pub struct IsdrChannel<T> {
    tx: T,
    logical_channel: u8,
    closed: AtomicBool,
}

impl<T> IsdrChannel<T>
where
    T: ApduTransmitter,
{
    /// Opens the default GSMA ISD-R application on a logical channel.
    ///
    /// # Errors
    ///
    /// Returns APDU transport, malformed response, or status-word errors from
    /// the Terminal Capability, channel-open, or SELECT commands.
    pub async fn open(tx: T) -> Result<Self> {
        Self::open_with_aid(tx, &GSMA_ISD_R_AID).await
    }

    /// Opens a logical channel and selects an explicit ISD-R AID.
    ///
    /// # Errors
    ///
    /// Returns APDU transport, malformed response, or status-word errors. If
    /// SELECT fails after a channel was opened, this method attempts to close
    /// that channel before returning the SELECT error.
    pub async fn open_with_aid(tx: T, aid: &[u8]) -> Result<Self> {
        if aid.len() > MAX_SHORT_APDU_DATA_LENGTH {
            return Err(EuiccError::Apdu(uicc::apdu::ApduError::DataTooLong {
                got: aid.len(),
            }));
        }

        send_terminal_capability(&tx).await?;
        let logical_channel = open_logical_channel(&tx).await?;
        if let Err(err) = select_aid(&tx, logical_channel, aid).await {
            let _close_result = close_logical_channel(&tx, logical_channel).await;
            return Err(err);
        }

        Ok(Self {
            tx,
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
impl<T> ApduTransmitter for IsdrChannel<T>
where
    T: ApduTransmitter,
{
    async fn transmit(&self, request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
        self.tx.transmit(request).await
    }

    async fn close(&self) -> uicc::apdu::Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            close_logical_channel_raw(&self.tx, self.logical_channel).await?;
        }
        self.tx.close().await
    }
}

async fn send_terminal_capability<T>(tx: &T) -> Result<()>
where
    T: ApduTransmitter,
{
    let response = ApduResponse::new(tx.transmit(&TERMINAL_CAPABILITY_APDU).await?);
    let sw = response.status_word()?;
    if sw != StatusWord::OK && !sw.has_more() {
        return Err(EuiccError::Apdu(uicc::apdu::ApduError::Status(sw)));
    }
    Ok(())
}

async fn open_logical_channel<T>(tx: &T) -> Result<u8>
where
    T: ApduTransmitter,
{
    let request = ApduRequest::new(0x00, 0x70, 0x00, 0x00)
        .with_le(0x01)
        .to_bytes()?;
    let response = ApduResponse::new(tx.transmit(&request).await?);
    let sw = response.status_word()?;
    if sw != StatusWord::OK {
        return Err(EuiccError::Apdu(uicc::apdu::ApduError::Status(sw)));
    }

    let Some(&channel) = response.data().first() else {
        return Err(EuiccError::Apdu(uicc::apdu::ApduError::MalformedResponse));
    };
    if channel == 0 || channel > MAX_LOGICAL_CHANNEL {
        return Err(EuiccError::Apdu(uicc::apdu::ApduError::Transport(format!(
            "open logical channel returned invalid logical channel {channel}"
        ))));
    }
    Ok(channel)
}

async fn select_aid<T>(tx: &T, channel: u8, aid: &[u8]) -> Result<()>
where
    T: ApduTransmitter,
{
    let request = ApduRequest::new(class_byte_for_channel(0x00, channel)?, 0xA4, 0x04, 0x00)
        .with_data(aid.to_vec());
    let encoded = request.to_bytes()?;
    let response = ApduResponse::new(tx.transmit(&encoded).await?);
    let sw = response.status_word()?;
    if sw != StatusWord::OK && !sw.has_more() {
        return Err(EuiccError::Apdu(uicc::apdu::ApduError::Status(sw)));
    }
    Ok(())
}

async fn close_logical_channel<T>(tx: &T, channel: u8) -> Result<()>
where
    T: ApduTransmitter,
{
    Ok(close_logical_channel_raw(tx, channel).await?)
}

async fn close_logical_channel_raw<T>(tx: &T, channel: u8) -> uicc::apdu::Result<()>
where
    T: ApduTransmitter,
{
    if channel == 0 || channel > MAX_LOGICAL_CHANNEL {
        return Err(uicc::apdu::ApduError::Transport(format!(
            "invalid logical channel {channel}"
        )));
    }
    let request = ApduRequest::new(0x00, 0x70, 0x80, channel)
        .with_le(0x00)
        .to_bytes()?;
    let response = ApduResponse::new(tx.transmit(&request).await?);
    let sw = response.status_word()?;
    if sw != StatusWord::OK {
        return Err(uicc::apdu::ApduError::Status(sw));
    }
    Ok(())
}

fn class_byte_for_channel(cla: u8, channel: u8) -> Result<u8> {
    if channel < 4 {
        return Ok((cla & 0x9C) | channel);
    }
    if channel <= MAX_LOGICAL_CHANNEL {
        return Ok((cla & 0xB0) | 0x40 | (channel - 4));
    }
    Err(EuiccError::Apdu(uicc::apdu::ApduError::Transport(format!(
        "logical channel {channel} exceeds maximum {MAX_LOGICAL_CHANNEL}"
    ))))
}
