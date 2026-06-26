use crate::profile::ProfileInfo;
use crate::{EuiccError, Result, es9p};

/// Profile download stage reported through [`DownloadOptions`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DownloadStage {
    /// ES9+.AuthenticateClient and ES10b.AuthenticateServer phase.
    AuthenticateClient,
    /// ES10b.PrepareDownload and ES9+.GetBoundProfilePackage phase.
    AuthenticateServer,
    /// ES10b.LoadBoundProfilePackage transfer phase.
    Install,
}

impl DownloadStage {
    /// Returns a stable lowercase stage name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticateClient => "authenticate_client",
            Self::AuthenticateServer => "authenticate_server",
            Self::Install => "install",
        }
    }
}

/// Callbacks and optional user input for profile download.
#[derive(Clone, Copy, Default)]
pub struct DownloadOptions<'a> {
    /// Confirmation code already collected from the user.
    pub confirmation_code: Option<&'a str>,
    /// Called when profile metadata is available; return `false` to cancel.
    pub confirm_profile: Option<&'a dyn Fn(&ProfileInfo) -> bool>,
    /// Called when the profile requires a confirmation code and none was set.
    pub request_confirmation_code: Option<&'a dyn Fn() -> Option<String>>,
    /// Called before each major download stage starts.
    pub progress: Option<&'a dyn Fn(DownloadStage)>,
}
pub(super) fn emit_progress(options: &DownloadOptions<'_>, stage: DownloadStage) {
    if let Some(progress) = options.progress {
        progress(stage);
    }
}

pub(super) fn should_cancel_profile(options: &DownloadOptions<'_>, metadata: &ProfileInfo) -> bool {
    options
        .confirm_profile
        .is_some_and(|confirm| !confirm(metadata))
}

pub(super) fn profile_metadata(response: &es9p::AuthenticateClientResponse) -> Result<ProfileInfo> {
    let tlv = response
        .profile_metadata
        .as_ref()
        .ok_or(EuiccError::MissingField("profileMetadata"))?;
    ProfileInfo::from_tlv(tlv)
}

pub(super) fn confirmation_code(
    options: &DownloadOptions<'_>,
    response: &es9p::AuthenticateClientResponse,
) -> Result<Option<Vec<u8>>> {
    let request = response.prepare_download_request(None);
    if !request.need_confirmation_code() {
        return Ok(None);
    }
    if let Some(code) = options.confirmation_code {
        return Ok(Some(code.as_bytes().to_vec()));
    }
    let prompted = options
        .request_confirmation_code
        .and_then(|prompt| prompt())
        .filter(|code| !code.is_empty());
    if let Some(code) = prompted {
        return Ok(Some(code.into_bytes()));
    }
    Err(EuiccError::MissingField("confirmationCode"))
}
