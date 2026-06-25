use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use uicc::apdu::ApduTransmitter;

use crate::error::{EuiccError, Result};

use super::GSMA_ISD_R_AID;
use super::transport::{apdu_transport_error, validate_logical_channel};

/// ISD-R logical channel opened through a `uicc-rs` QMI UIM reader.
///
/// # Arguments
///
/// The generic `T` is the QCOM transport owned by [`uicc::qcom::uim::Reader`].
///
/// # Returns
///
/// A transmitter wrapper that forwards APDUs through QMI UIM logical-channel
/// commands.
///
/// # Errors
///
/// Opening the channel returns QCOM transport, slot-activation, or UIM errors.
///
/// # Examples
///
/// ```no_run
/// # async fn demo<T>(reader: uicc::qcom::uim::Reader<T>) -> euicc::Result<()>
/// # where
/// #     T: uicc::qcom::Transport,
/// # {
/// let channel = euicc::apdu::QcomIsdrChannel::open(reader).await?;
/// assert!(channel.logical_channel() > 0);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct QcomIsdrChannel<T>
where
    T: uicc::qcom::Transport,
{
    reader: uicc::qcom::uim::Reader<T>,
    logical_channel: u8,
    closed: AtomicBool,
}

impl<T> QcomIsdrChannel<T>
where
    T: uicc::qcom::Transport,
{
    /// Activates the configured slot and opens the default GSMA ISD-R AID.
    ///
    /// # Arguments
    ///
    /// * `reader` - A QMI UIM reader from `uicc-rs`.
    ///
    /// # Returns
    ///
    /// A [`QcomIsdrChannel`] wrapping `reader` and the assigned logical
    /// channel.
    ///
    /// # Errors
    ///
    /// Returns QCOM transport, slot-activation, logical-channel, or UIM card
    /// errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::qcom::uim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::qcom::Transport,
    /// # {
    /// let channel = euicc::apdu::QcomIsdrChannel::open(reader).await?;
    /// assert!(channel.logical_channel() <= 19);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open(reader: uicc::qcom::uim::Reader<T>) -> Result<Self> {
        Self::open_with_aid(reader, &GSMA_ISD_R_AID).await
    }

    /// Activates the configured slot and opens an explicit ISD-R AID.
    ///
    /// # Arguments
    ///
    /// * `reader` - A QMI UIM reader from `uicc-rs`.
    /// * `aid` - ISD-R application identifier to select.
    ///
    /// # Returns
    ///
    /// A [`QcomIsdrChannel`] wrapping `reader` and the assigned logical
    /// channel.
    ///
    /// # Errors
    ///
    /// Returns QCOM transport, slot-activation, logical-channel, or UIM card
    /// errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::qcom::uim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::qcom::Transport,
    /// # {
    /// let channel = euicc::apdu::QcomIsdrChannel::open_with_aid(
    ///     reader,
    ///     &euicc::apdu::GSMA_ISD_R_AID,
    /// )
    /// .await?;
    /// assert!(channel.logical_channel() > 0);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_with_aid(reader: uicc::qcom::uim::Reader<T>, aid: &[u8]) -> Result<Self> {
        reader
            .activate_slot()
            .await
            .map_err(|err| EuiccError::Apdu(apdu_transport_error("QCOM", err)))?;
        let channel = reader
            .open_logical_channel(aid)
            .await
            .map_err(|err| EuiccError::Apdu(apdu_transport_error("QCOM", err)))?;
        validate_logical_channel(channel)?;
        Ok(Self {
            reader,
            logical_channel: channel,
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
    /// Logical channel number assigned by QMI UIM.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::qcom::uim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::qcom::Transport,
    /// # {
    /// let channel = euicc::apdu::QcomIsdrChannel::open(reader).await?;
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
impl<T> ApduTransmitter for QcomIsdrChannel<T>
where
    T: uicc::qcom::Transport,
{
    async fn transmit(&self, request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
        self.reader
            .send_apdu(self.logical_channel, request)
            .await
            .map_err(|err| apdu_transport_error("QCOM", err))
    }

    async fn close(&self) -> uicc::apdu::Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.reader
                .close_logical_channel(self.logical_channel)
                .await
                .map_err(|err| apdu_transport_error("QCOM", err))?;
        }
        self.reader
            .close()
            .await
            .map_err(|err| apdu_transport_error("QCOM", err))
    }
}
