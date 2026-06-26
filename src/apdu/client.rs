use uicc::apdu::{ApduRequest, ApduResponse, ApduTransmitter, StatusWord};

use crate::bertlv::Tlv;
use crate::error::{EuiccError, Result};

use super::{
    CardRequest, CardResponse, GSMA_ISD_R_AID, IsdrChannel, MbimIsdrChannel, QcomIsdrChannel,
};

/// ES10 APDU adapter over a `uicc` APDU transmitter.
///
/// # Errors
///
/// Construction returns [`EuiccError::MalformedTlv`] when the max segment size
/// is zero or exceeds short-APDU limits.
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
    /// # Errors
    ///
    /// Returns [`EuiccError::MalformedTlv`] when `max_segment_size` is zero or
    /// greater than 255.
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
    #[must_use]
    pub const fn with_logical_channel(mut self, logical_channel: u8) -> Self {
        self.logical_channel = Some(logical_channel);
        self
    }

    /// Returns the max segment size.
    #[must_use]
    pub const fn max_segment_size(&self) -> usize {
        self.max_segment_size
    }

    /// Returns the configured logical channel.
    #[must_use]
    pub const fn logical_channel(&self) -> Option<u8> {
        self.logical_channel
    }

    /// Sends a typed card request and decodes its typed response.
    ///
    /// # Errors
    ///
    /// Returns TLV encoding, APDU transport, response decoding, or card
    /// validation errors.
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
    /// # Errors
    ///
    /// Returns APDU encoding, APDU transport, malformed response, or unexpected
    /// status-word errors.
    pub async fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let chunk_count = command.len().div_ceil(self.max_segment_size);
        for (index, chunk) in command.chunks(self.max_segment_size).enumerate() {
            let is_last = index + 1 == chunk_count;
            let cla = self.class_byte(0x80)?;
            let request =
                ApduRequest::new(cla, 0xE2, if is_last { 0x91 } else { 0x11 }, index as u8)
                    .with_data(chunk.to_vec())?
                    .with_le(0x00);
            let encoded = request.to_bytes();
            let response = ApduResponse::new(self.tx.transmit(&encoded).await?)?;
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
    /// # Errors
    ///
    /// Returns the underlying APDU close error.
    pub async fn close(&self) -> Result<()> {
        Ok(self.tx.close().await?)
    }

    async fn read_command_response(&self, mut le: u8, out: &mut Vec<u8>) -> Result<()> {
        loop {
            let request = ApduRequest::new(self.class_byte(0x80)?, 0xC0, 0x00, 0x00).with_le(le);
            let encoded = request.to_bytes();
            let response = ApduResponse::new(self.tx.transmit(&encoded).await?)?;
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

    fn class_byte(&self, cla: u8) -> Result<u8> {
        let Some(channel) = self.logical_channel else {
            return Ok(cla);
        };
        if channel < 4 {
            return Ok((cla & 0x9C) | channel);
        } else if channel < 20 {
            return Ok((cla & 0xB0) | 0x40 | (channel - 4));
        }
        Err(EuiccError::Apdu(uicc::apdu::ApduError::Transport(format!(
            "logical channel {channel} exceeds maximum 19"
        ))))
    }
}

impl<T> EuiccApdu<IsdrChannel<T>>
where
    T: ApduTransmitter,
{
    /// Opens the default GSMA ISD-R application and creates an ES10 APDU adapter.
    ///
    /// # Errors
    ///
    /// Returns channel-open errors or invalid `max_segment_size` errors.
    pub async fn open(tx: T, max_segment_size: usize) -> Result<Self> {
        Self::open_with_aid(tx, &GSMA_ISD_R_AID, max_segment_size).await
    }

    /// Opens an explicit ISD-R AID and creates an ES10 APDU adapter.
    ///
    /// # Errors
    ///
    /// Returns channel-open errors or invalid `max_segment_size` errors.
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
    /// # Errors
    ///
    /// Returns MBIM channel-open errors or invalid `max_segment_size` errors.
    pub async fn open_mbim(reader: uicc::mbim::Reader<T>, max_segment_size: usize) -> Result<Self> {
        Self::open_mbim_with_aid(reader, &GSMA_ISD_R_AID, max_segment_size).await
    }

    /// Opens an explicit ISD-R AID through MBIM.
    ///
    /// # Errors
    ///
    /// Returns MBIM channel-open errors or invalid `max_segment_size` errors.
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
    /// # Errors
    ///
    /// Returns QCOM channel-open errors or invalid `max_segment_size` errors.
    pub async fn open_qcom(
        reader: uicc::qcom::uim::Reader<T>,
        max_segment_size: usize,
    ) -> Result<Self> {
        Self::open_qcom_with_aid(reader, &GSMA_ISD_R_AID, max_segment_size).await
    }

    /// Opens an explicit ISD-R AID through QMI UIM.
    ///
    /// # Errors
    ///
    /// Returns QCOM channel-open errors or invalid `max_segment_size` errors.
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
