use uicc::apdu::{ApduRequest, ApduResponse, ApduTransmitter, StatusWord};

use crate::bertlv::Tlv;
use crate::error::{EuiccError, Result};

use super::{
    CardRequest, CardResponse, GSMA_ISD_R_AID, IsdrChannel, MbimIsdrChannel, QcomIsdrChannel,
};

/// ES10 APDU adapter over a `uicc` APDU transmitter.
///
/// # Arguments
///
/// Build with [`EuiccApdu::new`] and pass any [`ApduTransmitter`] implementation
/// from the `uicc` crate.
///
/// # Returns
///
/// A high-level eUICC APDU adapter that handles STORE DATA segmentation and
/// GET RESPONSE loops.
///
/// # Errors
///
/// Construction returns [`EuiccError::MalformedTlv`] when the max segment size
/// is zero or exceeds short-APDU limits.
///
/// # Examples
///
/// ```
/// # use async_trait::async_trait;
/// # struct Tx;
/// # #[async_trait]
/// # impl uicc::apdu::ApduTransmitter for Tx {
/// #     async fn transmit(&self, _request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
/// #         Ok(vec![0x90, 0x00])
/// #     }
/// #     async fn close(&self) -> uicc::apdu::Result<()> { Ok(()) }
/// # }
/// let adapter = euicc::apdu::EuiccApdu::new(Tx, 255)?;
/// assert_eq!(adapter.max_segment_size(), 255);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone)]
pub struct EuiccApdu<T> {
    tx: T,
    max_segment_size: usize,
    logical_channel: Option<u8>,
}

impl<T> EuiccApdu<T>
where
    T: ApduTransmitter,
{
    /// Creates an ES10 APDU adapter.
    ///
    /// # Arguments
    ///
    /// * `tx` - Underlying APDU transmitter.
    /// * `max_segment_size` - Maximum STORE DATA command payload size, from
    ///   1 to 255 bytes.
    ///
    /// # Returns
    ///
    /// A new [`EuiccApdu`] adapter.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::MalformedTlv`] when `max_segment_size` is zero or
    /// greater than 255.
    ///
    /// # Examples
    ///
    /// ```
    /// # use async_trait::async_trait;
    /// # struct Tx;
    /// # #[async_trait]
    /// # impl uicc::apdu::ApduTransmitter for Tx {
    /// #     async fn transmit(&self, _request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
    /// #         Ok(vec![0x90, 0x00])
    /// #     }
    /// #     async fn close(&self) -> uicc::apdu::Result<()> { Ok(()) }
    /// # }
    /// let adapter = euicc::apdu::EuiccApdu::new(Tx, 128)?;
    /// assert_eq!(adapter.max_segment_size(), 128);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn new(tx: T, max_segment_size: usize) -> Result<Self> {
        if max_segment_size == 0 || max_segment_size > u8::MAX as usize {
            return Err(EuiccError::MalformedTlv("invalid max segment size"));
        }
        Ok(Self {
            tx,
            max_segment_size,
            logical_channel: None,
        })
    }

    /// Sets the logical channel encoded into the APDU class byte.
    ///
    /// # Arguments
    ///
    /// * `logical_channel` - ISO 7816 logical channel from `0` to `19`.
    ///
    /// # Returns
    ///
    /// The updated adapter.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// # use async_trait::async_trait;
    /// # struct Tx;
    /// # #[async_trait]
    /// # impl uicc::apdu::ApduTransmitter for Tx {
    /// #     async fn transmit(&self, _request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
    /// #         Ok(vec![0x90, 0x00])
    /// #     }
    /// #     async fn close(&self) -> uicc::apdu::Result<()> { Ok(()) }
    /// # }
    /// let adapter = euicc::apdu::EuiccApdu::new(Tx, 255)?.with_logical_channel(1);
    /// assert_eq!(adapter.logical_channel(), Some(1));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub const fn with_logical_channel(mut self, logical_channel: u8) -> Self {
        self.logical_channel = Some(logical_channel);
        self
    }

    /// Returns the max segment size.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// The maximum STORE DATA payload size.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// # use async_trait::async_trait;
    /// # struct Tx;
    /// # #[async_trait]
    /// # impl uicc::apdu::ApduTransmitter for Tx {
    /// #     async fn transmit(&self, _request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
    /// #         Ok(vec![0x90, 0x00])
    /// #     }
    /// #     async fn close(&self) -> uicc::apdu::Result<()> { Ok(()) }
    /// # }
    /// let adapter = euicc::apdu::EuiccApdu::new(Tx, 200)?;
    /// assert_eq!(adapter.max_segment_size(), 200);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub const fn max_segment_size(&self) -> usize {
        self.max_segment_size
    }

    /// Returns the configured logical channel.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Optional logical channel encoded into APDU class bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// # use async_trait::async_trait;
    /// # struct Tx;
    /// # #[async_trait]
    /// # impl uicc::apdu::ApduTransmitter for Tx {
    /// #     async fn transmit(&self, _request: &[u8]) -> uicc::apdu::Result<Vec<u8>> {
    /// #         Ok(vec![0x90, 0x00])
    /// #     }
    /// #     async fn close(&self) -> uicc::apdu::Result<()> { Ok(()) }
    /// # }
    /// let adapter = euicc::apdu::EuiccApdu::new(Tx, 255)?.with_logical_channel(3);
    /// assert_eq!(adapter.logical_channel(), Some(3));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub const fn logical_channel(&self) -> Option<u8> {
        self.logical_channel
    }

    /// Sends a typed card request and decodes its typed response.
    ///
    /// # Arguments
    ///
    /// * `request` - ES10 card request.
    ///
    /// # Returns
    ///
    /// The decoded and validated response.
    ///
    /// # Errors
    ///
    /// Returns TLV encoding, APDU transport, response decoding, or card
    /// validation errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T: uicc::apdu::ApduTransmitter>(
    /// #     adapter: &euicc::apdu::EuiccApdu<T>,
    /// # ) -> euicc::Result<()> {
    /// let response = adapter
    ///     .transmit(&euicc::es10b::GetEuiccChallengeRequest)
    ///     .await?;
    /// assert!(!response.challenge.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn transmit<R>(&self, request: &R) -> Result<R::Response>
    where
        R: CardRequest + Sync,
    {
        let command = request.to_tlv()?.to_bytes()?;
        let response = self.transmit_raw(&command).await?;
        let tlv = Tlv::from_bytes(&response)?;
        let decoded = request.decode_response(&tlv)?;
        decoded.validate()?;
        Ok(decoded)
    }

    /// Sends raw ES10 TLV command bytes and returns raw TLV response bytes.
    ///
    /// # Arguments
    ///
    /// * `command` - Encoded ES10 BER-TLV command bytes.
    ///
    /// # Returns
    ///
    /// Concatenated response data bytes without the APDU status word.
    ///
    /// # Errors
    ///
    /// Returns APDU encoding, APDU transport, malformed response, or unexpected
    /// status-word errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T: uicc::apdu::ApduTransmitter>(
    /// #     adapter: &euicc::apdu::EuiccApdu<T>,
    /// # ) -> euicc::Result<()> {
    /// let bytes = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(46),
    ///     Vec::new(),
    /// )?
    /// .to_bytes()?;
    /// let _response = adapter.transmit_raw(&bytes).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let chunk_count = command.len().div_ceil(self.max_segment_size);
        for (index, chunk) in command.chunks(self.max_segment_size).enumerate() {
            let is_last = index + 1 == chunk_count;
            let mut request =
                ApduRequest::new(0x80, 0xE2, if is_last { 0x91 } else { 0x11 }, index as u8)
                    .with_data(chunk.to_vec())
                    .with_le(0x00);
            self.apply_logical_channel(&mut request);
            let encoded = request.to_bytes()?;
            let response = ApduResponse::new(self.tx.transmit(&encoded).await?);
            response.require_status()?;
            out.extend_from_slice(response.data());
            if response.has_more()? {
                self.read_command_response(response.sw2()?, &mut out)
                    .await?;
                continue;
            }
            let sw = response.status_word()?;
            if !accepted_es10_status(sw) {
                return Err(EuiccError::Apdu(uicc::apdu::ApduError::Status(sw)));
            }
        }
        Ok(out)
    }

    /// Closes the underlying APDU transmitter.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the underlying transmitter closes successfully.
    ///
    /// # Errors
    ///
    /// Returns the underlying APDU close error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T: uicc::apdu::ApduTransmitter>(
    /// #     adapter: &euicc::apdu::EuiccApdu<T>,
    /// # ) -> euicc::Result<()> {
    /// adapter.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn close(&self) -> Result<()> {
        Ok(self.tx.close().await?)
    }

    async fn read_command_response(&self, mut le: u8, out: &mut Vec<u8>) -> Result<()> {
        loop {
            let mut request = ApduRequest::new(0x80, 0xC0, 0x00, 0x00).with_le(le);
            self.apply_logical_channel(&mut request);
            let encoded = request.to_bytes()?;
            let response = ApduResponse::new(self.tx.transmit(&encoded).await?);
            response.require_status()?;
            out.extend_from_slice(response.data());
            if response.has_more()? {
                le = response.sw2()?;
                continue;
            }
            let sw = response.status_word()?;
            if !accepted_es10_status(sw) {
                return Err(EuiccError::Apdu(uicc::apdu::ApduError::Status(sw)));
            }
            return Ok(());
        }
    }

    fn apply_logical_channel(&self, request: &mut ApduRequest) {
        let Some(channel) = self.logical_channel else {
            return;
        };
        if channel < 4 {
            request.cla = (request.cla & 0x9C) | channel;
        } else if channel < 20 {
            request.cla = (request.cla & 0xB0) | 0x40 | (channel - 4);
        }
    }
}

impl<T> EuiccApdu<IsdrChannel<T>>
where
    T: ApduTransmitter,
{
    /// Opens the default GSMA ISD-R application and creates an ES10 APDU adapter.
    ///
    /// # Arguments
    ///
    /// * `tx` - Raw APDU transmitter from `uicc-rs`.
    /// * `max_segment_size` - Maximum STORE DATA command payload size.
    ///
    /// # Returns
    ///
    /// A [`EuiccApdu`] adapter bound to the opened ISD-R logical channel.
    ///
    /// # Errors
    ///
    /// Returns channel-open errors or invalid `max_segment_size` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T: uicc::apdu::ApduTransmitter>(tx: T) -> euicc::Result<()> {
    /// let adapter = euicc::apdu::EuiccApdu::open(tx, 254).await?;
    /// assert!(adapter.logical_channel().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open(tx: T, max_segment_size: usize) -> Result<Self> {
        Self::open_with_aid(tx, &GSMA_ISD_R_AID, max_segment_size).await
    }

    /// Opens an explicit ISD-R AID and creates an ES10 APDU adapter.
    ///
    /// # Arguments
    ///
    /// * `tx` - Raw APDU transmitter from `uicc-rs`.
    /// * `aid` - ISD-R application identifier to select.
    /// * `max_segment_size` - Maximum STORE DATA command payload size.
    ///
    /// # Returns
    ///
    /// A [`EuiccApdu`] adapter bound to the opened ISD-R logical channel.
    ///
    /// # Errors
    ///
    /// Returns channel-open errors or invalid `max_segment_size` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T: uicc::apdu::ApduTransmitter>(tx: T) -> euicc::Result<()> {
    /// let adapter = euicc::apdu::EuiccApdu::open_with_aid(
    ///     tx,
    ///     &euicc::apdu::GSMA_ISD_R_AID,
    ///     254,
    /// )
    /// .await?;
    /// assert!(adapter.logical_channel().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_with_aid(tx: T, aid: &[u8], max_segment_size: usize) -> Result<Self> {
        let channel = IsdrChannel::open_with_aid(tx, aid).await?;
        let logical_channel = channel.logical_channel();
        Ok(Self::new(channel, max_segment_size)?.with_logical_channel(logical_channel))
    }
}

impl<T> EuiccApdu<MbimIsdrChannel<T>>
where
    T: uicc::mbim::MbimTransport,
{
    /// Opens the default GSMA ISD-R application through MBIM.
    ///
    /// # Arguments
    ///
    /// * `reader` - Initialized MBIM reader, typically returned by
    ///   [`uicc::mbim::open`].
    /// * `max_segment_size` - Maximum STORE DATA command payload size.
    ///
    /// # Returns
    ///
    /// A [`EuiccApdu`] adapter bound to the opened MBIM ISD-R logical channel.
    ///
    /// # Errors
    ///
    /// Returns MBIM channel-open errors or invalid `max_segment_size` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::mbim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::mbim::MbimTransport,
    /// # {
    /// let adapter = euicc::apdu::EuiccApdu::open_mbim(reader, 254).await?;
    /// assert!(adapter.logical_channel().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_mbim(reader: uicc::mbim::Reader<T>, max_segment_size: usize) -> Result<Self> {
        Self::open_mbim_with_aid(reader, &GSMA_ISD_R_AID, max_segment_size).await
    }

    /// Opens an explicit ISD-R AID through MBIM.
    ///
    /// # Arguments
    ///
    /// * `reader` - Initialized MBIM reader.
    /// * `aid` - ISD-R application identifier to select.
    /// * `max_segment_size` - Maximum STORE DATA command payload size.
    ///
    /// # Returns
    ///
    /// A [`EuiccApdu`] adapter bound to the opened MBIM ISD-R logical channel.
    ///
    /// # Errors
    ///
    /// Returns MBIM channel-open errors or invalid `max_segment_size` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::mbim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::mbim::MbimTransport,
    /// # {
    /// let adapter = euicc::apdu::EuiccApdu::open_mbim_with_aid(
    ///     reader,
    ///     &euicc::apdu::GSMA_ISD_R_AID,
    ///     254,
    /// )
    /// .await?;
    /// assert!(adapter.logical_channel().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_mbim_with_aid(
        reader: uicc::mbim::Reader<T>,
        aid: &[u8],
        max_segment_size: usize,
    ) -> Result<Self> {
        let channel = MbimIsdrChannel::open_with_aid(reader, aid).await?;
        let logical_channel = channel.logical_channel();
        Ok(Self::new(channel, max_segment_size)?.with_logical_channel(logical_channel))
    }
}

impl<T> EuiccApdu<QcomIsdrChannel<T>>
where
    T: uicc::qcom::Transport,
{
    /// Opens the default GSMA ISD-R application through QMI UIM.
    ///
    /// # Arguments
    ///
    /// * `reader` - QMI UIM reader from `uicc-rs`.
    /// * `max_segment_size` - Maximum STORE DATA command payload size.
    ///
    /// # Returns
    ///
    /// A [`EuiccApdu`] adapter bound to the opened QCOM ISD-R logical channel.
    ///
    /// # Errors
    ///
    /// Returns QCOM channel-open errors or invalid `max_segment_size` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::qcom::uim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::qcom::Transport,
    /// # {
    /// let adapter = euicc::apdu::EuiccApdu::open_qcom(reader, 254).await?;
    /// assert!(adapter.logical_channel().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_qcom(
        reader: uicc::qcom::uim::Reader<T>,
        max_segment_size: usize,
    ) -> Result<Self> {
        Self::open_qcom_with_aid(reader, &GSMA_ISD_R_AID, max_segment_size).await
    }

    /// Opens an explicit ISD-R AID through QMI UIM.
    ///
    /// # Arguments
    ///
    /// * `reader` - QMI UIM reader from `uicc-rs`.
    /// * `aid` - ISD-R application identifier to select.
    /// * `max_segment_size` - Maximum STORE DATA command payload size.
    ///
    /// # Returns
    ///
    /// A [`EuiccApdu`] adapter bound to the opened QCOM ISD-R logical channel.
    ///
    /// # Errors
    ///
    /// Returns QCOM channel-open errors or invalid `max_segment_size` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T>(reader: uicc::qcom::uim::Reader<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::qcom::Transport,
    /// # {
    /// let adapter = euicc::apdu::EuiccApdu::open_qcom_with_aid(
    ///     reader,
    ///     &euicc::apdu::GSMA_ISD_R_AID,
    ///     254,
    /// )
    /// .await?;
    /// assert!(adapter.logical_channel().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_qcom_with_aid(
        reader: uicc::qcom::uim::Reader<T>,
        aid: &[u8],
        max_segment_size: usize,
    ) -> Result<Self> {
        let channel = QcomIsdrChannel::open_with_aid(reader, aid).await?;
        let logical_channel = channel.logical_channel();
        Ok(Self::new(channel, max_segment_size)?.with_logical_channel(logical_channel))
    }
}

fn accepted_es10_status(sw: StatusWord) -> bool {
    sw.sw1() == 0x90 || sw.sw1() == 0x91
}
