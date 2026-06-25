use std::fmt;

use crate::error::{EuiccError, Result};

use super::MAX_LOGICAL_CHANNEL;

pub(super) fn apdu_transport_error(source: &str, err: impl fmt::Display) -> uicc::apdu::ApduError {
    uicc::apdu::ApduError::Transport(format!("{source}: {err}"))
}

pub(super) fn validate_logical_channel(channel: u8) -> Result<()> {
    if channel == 0 || channel > MAX_LOGICAL_CHANNEL {
        return Err(EuiccError::Apdu(uicc::apdu::ApduError::Transport(format!(
            "invalid logical channel {channel}"
        ))));
    }
    Ok(())
}
