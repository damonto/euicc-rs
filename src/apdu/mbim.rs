use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use uicc::apdu::{ApduTransmitter, StatusWord};

use crate::error::{EuiccError, Result};

use super::GSMA_ISD_R_AID;
use super::transport::{apdu_transport_error, validate_logical_channel};

/// ISD-R logical channel opened through a `uicc-rs` MBIM reader.
///
/// # Arguments
///
/// The generic `T` is the MBIM transport owned by [`uicc::mbim::Reader`].
///
/// # Returns
///
/// A transmitter wrapper that converts MBIM UICC APDU results into standard
/// APDU response bytes for ES10 commands.
///
/// # Errors
///
/// Opening the channel returns MBIM transport, UICC status, or logical-channel
/// validation errors.
///
/// # Examples
///
/// ```no_run
/// # async fn demo<T>(reader: uicc::mbim::Reader<T>) -> euicc::Result<()>
/// # where
/// #     T: uicc::mbim::MbimTransport,
/// # {
/// let channel = euicc::apdu::MbimIsdrChannel::open(reader).await?;
/// assert!(channel.logical_channel() > 0);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct MbimIsdrChannel<T>
where
    T: uicc::mbim::MbimTransport,
{
    reader: uicc::mbim::Reader<T>,
    logical_channel: u8,
    closed: AtomicBool,
}

impl<T> MbimIsdrChannel<T>
where
    T: uicc::mbim::MbimTransport,
{
    /// Opens the default GSMA ISD-R application on an MBIM logical channel.
    ///
    /// # Arguments
    ///
    /// * `reader` - An initialized MBIM reader, typically returned by
    ///   [`uicc::mbim::open`].
    ///
    /// # Returns
    ///
    /// An [`MbimIsdrChannel`] wrapping `reader` and the assigned logical
    /// channel.
    ///
    /// # Errors
    ///
    /// Returns MBIM transport, UICC status, or invalid logical-channel errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::mbim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::mbim::MbimTransport,
    /// # {
    /// let channel = euicc::apdu::MbimIsdrChannel::open(reader).await?;
    /// assert!(channel.logical_channel() <= 19);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open(reader: uicc::mbim::Reader<T>) -> Result<Self> {
        Self::open_with_aid(reader, &GSMA_ISD_R_AID).await
    }

    /// Opens an explicit ISD-R AID on an MBIM logical channel.
    ///
    /// # Arguments
    ///
    /// * `reader` - An initialized MBIM reader.
    /// * `aid` - ISD-R application identifier to select.
    ///
    /// # Returns
    ///
    /// An [`MbimIsdrChannel`] wrapping `reader` and the assigned logical
    /// channel.
    ///
    /// # Errors
    ///
    /// Returns MBIM transport, UICC status, or invalid logical-channel errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::mbim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::mbim::MbimTransport,
    /// # {
    /// let channel = euicc::apdu::MbimIsdrChannel::open_with_aid(
    ///     reader,
    ///     &euicc::apdu::GSMA_ISD_R_AID,
    /// )
    /// .await?;
    /// assert!(channel.logical_channel() > 0);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_with_aid(reader: uicc::mbim::Reader<T>, aid: &[u8]) -> Result<Self> {
        let channel = reader
            .open_channel(aid)
            .await
            .map_err(|err| EuiccError::Apdu(apdu_transport_error("MBIM", err)))?;
        Ok(Self {
            reader,
            logical_channel: mbim_logical_channel(channel)?,
            closed: AtomicBool::new(false),
        })
    }

    /// Returns the logical channel selected for ISD-R.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Logical channel number assigned by the MBIM backend.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::mbim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::mbim::MbimTransport,
    /// # {
    /// let channel = euicc::apdu::MbimIsdrChannel::open(reader).await?;
    /// assert_ne!(channel.logical_channel(), 0);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub const fn logical_channel(&self) -> u8 {
        self.logical_channel
    }
}

#[async_trait]
impl<T> ApduTransmitter for MbimIsdrChannel<T>
where
    T: uicc::mbim::MbimTransport,
{
    async fn transmit(&self, request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
        let (response, status) = self
            .reader
            .transmit_apdu(u32::from(self.logical_channel), request)
            .await
            .map_err(|err| apdu_transport_error("MBIM", err))?;
        Ok(mbim_apdu_response(response, status))
    }

    async fn close(&self) -> uicc::apdu::Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.reader
                .close_channel(u32::from(self.logical_channel))
                .await
                .map_err(|err| apdu_transport_error("MBIM", err))?;
        }
        self.reader
            .close()
            .await
            .map_err(|err| apdu_transport_error("MBIM", err))
    }
}

pub(super) fn mbim_apdu_response(mut response: Vec<u8>, status: u32) -> Vec<u8> {
    let sw = if status == 0 {
        StatusWord::OK
    } else {
        uicc::mbim::uicc_status_word(status)
    };
    response.extend_from_slice(&[sw.sw1(), sw.sw2()]);
    response
}

pub(super) fn mbim_logical_channel(channel: u32) -> Result<u8> {
    let channel = u8::try_from(channel).map_err(|_| {
        EuiccError::Apdu(uicc::apdu::ApduError::Transport(format!(
            "MBIM logical channel {channel} exceeds u8 range"
        )))
    })?;
    validate_logical_channel(channel)?;
    Ok(channel)
}
