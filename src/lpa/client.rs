use serde::{Serialize, de::DeserializeOwned};
use uicc::apdu::ApduTransmitter;
use url::Url;

use crate::apdu::EuiccApdu;
use crate::bertlv::{Tag, Tlv};
use crate::bpp::segment_bound_profile_package;
use crate::es10a::{
    EuiccConfiguredAddressesRequest, EuiccConfiguredAddressesResponse, SetDefaultDpAddressRequest,
};
use crate::es10b::{
    AuthenticateServerRequest, CancelSessionReason, CancelSessionRequest, EuiccInfoVersion,
    GetEuiccChallengeRequest, GetEuiccInfoRequest, ListNotificationRequest,
    LoadBoundProfilePackageResponse, NotificationSearchCriterion, NotificationSentRequest,
    PrepareDownloadRequest, RetrieveNotificationsListRequest,
};
use crate::es10c::{
    EuiccMemoryResetRequest, GetEuiccDataRequest, ProfileIdentifier, ProfileInfoListRequest,
    ProfileOperation, ProfileOperationRequest, ProfileSearchCriterion, SetNicknameRequest,
};
use crate::identifier::{HexBytes, Iccid, Imei};
use crate::notification::{
    NotificationEvent, NotificationMetadata, PendingNotification, SequenceNumber,
};
use crate::profile::ProfileInfo;
use crate::{EuiccError, Result, es9p, es11};

use super::activation::ActivationCode;
use super::download::{
    DownloadOptions, DownloadStage, confirmation_code, emit_progress, profile_metadata,
    should_cancel_profile,
};
use super::http::{JsonHttpClient, ReqwestJsonHttpClient};
use super::server::{parse_server_url, server_authority};
use super::status::{RspExecutionStatus, check_rsp_status};

/// LPA client binding ES10 APDU and ES9+/ES11 HTTP transports.
///
/// # Errors
///
/// Construction does not fail; individual operations return APDU, JSON, or
/// protocol errors.
#[derive(Debug, Clone)]
pub struct Client<T, H> {
    apdu: EuiccApdu<T>,
    http: H,
}

impl<T, H> Client<T, H>
where
    T: ApduTransmitter,
    H: JsonHttpClient,
{
    /// Creates an LPA client from APDU and HTTP transports.
    #[must_use]
    pub const fn new(apdu: EuiccApdu<T>, http: H) -> Self {
        Self { apdu, http }
    }

    /// Returns the APDU adapter.
    #[must_use]
    pub const fn apdu(&self) -> &EuiccApdu<T> {
        &self.apdu
    }

    /// Returns the JSON HTTP client.
    #[must_use]
    pub const fn http(&self) -> &H {
        &self.http
    }

    /// Closes the underlying APDU adapter.
    ///
    /// # Errors
    ///
    /// Returns APDU close errors.
    pub async fn close(&self) -> Result<()> {
        self.apdu.close().await
    }

    /// Reads ES10a.GetEuiccConfiguredAddresses.
    ///
    /// # Errors
    ///
    /// Returns APDU or response decoding errors.
    pub async fn euicc_configured_addresses(&self) -> Result<EuiccConfiguredAddressesResponse> {
        self.apdu.transmit(&EuiccConfiguredAddressesRequest).await
    }

    /// Sets ES10a.SetDefaultDpAddress.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    pub async fn set_default_dp_address(&self, address: &str) -> Result<()> {
        self.apdu
            .transmit(&SetDefaultDpAddressRequest {
                default_dp_address: address.to_owned(),
            })
            .await
            .map(|_| ())
    }

    /// Reads ES10b.GetEuiccChallenge.
    ///
    /// # Errors
    ///
    /// Returns APDU or response decoding errors.
    pub async fn euicc_challenge(&self) -> Result<Vec<u8>> {
        self.apdu
            .transmit(&GetEuiccChallengeRequest)
            .await
            .map(|response| response.challenge)
    }

    /// Reads ES10b.GetEUICCInfo1.
    ///
    /// # Errors
    ///
    /// Returns APDU or response decoding errors.
    pub async fn euicc_info1(&self) -> Result<Tlv> {
        self.euicc_info(EuiccInfoVersion::V1).await
    }

    /// Reads ES10b.GetEUICCInfo2.
    ///
    /// # Errors
    ///
    /// Returns APDU or response decoding errors.
    pub async fn euicc_info2(&self) -> Result<Tlv> {
        self.euicc_info(EuiccInfoVersion::V2).await
    }

    /// Runs ES9+.InitiateAuthentication.
    ///
    /// # Errors
    ///
    /// Returns APDU, URL, HTTP, or JSON errors.
    pub async fn initiate_authentication(
        &self,
        address: &Url,
    ) -> Result<es9p::InitiateAuthenticationResponse> {
        let request = es9p::InitiateAuthenticationRequest {
            euicc_challenge: crate::identifier::OctetString::from_bytes(
                self.euicc_challenge().await?,
            ),
            euicc_info1: self.euicc_info1().await?,
            smdp_address: server_authority(address)?,
        };
        let url = request.url(address)?;
        self.send_json_checked(&url, &request).await
    }

    /// Runs ES10b.AuthenticateServer and ES9+.AuthenticateClient.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, JSON, or RSP status errors.
    pub async fn authenticate_client(
        &self,
        address: &Url,
        request: &AuthenticateServerRequest,
    ) -> Result<es9p::AuthenticateClientResponse> {
        let response = self.apdu.transmit(request).await?;
        let request = es9p::AuthenticateClientRequest {
            transaction_id: request.transaction_id.clone(),
            authenticate_server_response: response.response,
        };
        let url = request.url(address)?;
        self.send_json_checked(&url, &request).await
    }

    /// Runs ES10b.PrepareDownload and ES9+.GetBoundProfilePackage.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, JSON, or RSP status errors.
    pub async fn prepare_download(
        &self,
        address: &Url,
        request: &PrepareDownloadRequest,
    ) -> Result<es9p::GetBoundProfilePackageResponse> {
        let response = self.apdu.transmit(request).await?;
        let request = es9p::GetBoundProfilePackageRequest {
            transaction_id: request.transaction_id.clone(),
            prepare_download_response: response.response,
        };
        let url = request.url(address)?;
        self.send_json_checked(&url, &request).await
    }

    /// Installs a Bound Profile Package through ES10b.LoadBoundProfilePackage.
    ///
    /// # Errors
    ///
    /// Returns BPP validation, APDU transfer, TLV decoding, or card result
    /// errors.
    pub async fn install_bound_profile_package(
        &self,
        response: &es9p::GetBoundProfilePackageResponse,
    ) -> Result<LoadBoundProfilePackageResponse> {
        let segments = segment_bound_profile_package(&response.bound_profile_package)?;
        let mut final_response = None;
        for segment in segments {
            let response = self.apdu.transmit_raw(&segment).await?;
            if !response.is_empty() {
                final_response = Some(response);
                break;
            }
        }
        let response =
            final_response.ok_or(EuiccError::MalformedTlv("profile installation response"))?;
        let tlv = Tlv::from_bytes(&response)?;
        let decoded = LoadBoundProfilePackageResponse::from_tlv(&tlv)?;
        <LoadBoundProfilePackageResponse as crate::apdu::CardResponse>::validate(&decoded)?;
        Ok(decoded)
    }

    /// Downloads and installs a profile from an activation code.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, profile metadata, cancellation, or installation
    /// errors.
    pub async fn download_profile(
        &self,
        activation_code: &ActivationCode,
        imei: Imei,
        options: DownloadOptions<'_>,
    ) -> Result<LoadBoundProfilePackageResponse> {
        emit_progress(&options, DownloadStage::AuthenticateClient);
        let initiate = self.initiate_authentication(&activation_code.smdp).await?;
        let authenticate_request =
            initiate.authenticate_server_request(imei, activation_code.matching_id.clone());
        let client_response = self
            .authenticate_client(&activation_code.smdp, &authenticate_request)
            .await?;
        let metadata = profile_metadata(&client_response)?;
        if should_cancel_profile(&options, &metadata) {
            self.cancel_session(
                &activation_code.smdp,
                client_response.transaction_id.clone(),
                CancelSessionReason::Postponed,
            )
            .await?;
            return Err(EuiccError::Canceled);
        }

        let confirmation_code = confirmation_code(&options, &client_response)?;
        let prepare_request = client_response.prepare_download_request(confirmation_code);

        emit_progress(&options, DownloadStage::AuthenticateServer);
        let bpp_response = match self
            .prepare_download(&activation_code.smdp, &prepare_request)
            .await
        {
            Ok(response) => response,
            Err(err) => {
                let _cancel_result = self
                    .cancel_session(
                        &activation_code.smdp,
                        client_response.transaction_id,
                        CancelSessionReason::Postponed,
                    )
                    .await;
                return Err(err);
            }
        };

        emit_progress(&options, DownloadStage::Install);
        match self.install_bound_profile_package(&bpp_response).await {
            Ok(response) => Ok(response),
            Err(err) => {
                let _cancel_result = self
                    .cancel_session(
                        &activation_code.smdp,
                        bpp_response.transaction_id,
                        CancelSessionReason::LoadBppExecutionError,
                    )
                    .await;
                Err(err)
            }
        }
    }

    /// Lists notification metadata from ES10b.ListNotification.
    ///
    /// # Errors
    ///
    /// Returns APDU or decoding errors.
    pub async fn list_notifications(
        &self,
        filter: Option<Vec<NotificationEvent>>,
    ) -> Result<Vec<NotificationMetadata>> {
        self.apdu
            .transmit(&ListNotificationRequest { filter })
            .await
            .map(|response| response.notifications)
    }

    /// Retrieves pending notifications from ES10b.RetrieveNotificationsList.
    ///
    /// # Errors
    ///
    /// Returns APDU or decoding errors.
    pub async fn retrieve_notifications(
        &self,
        search_criterion: Option<NotificationSearchCriterion>,
    ) -> Result<Vec<PendingNotification>> {
        self.apdu
            .transmit(&RetrieveNotificationsListRequest { search_criterion })
            .await
            .map(|response| response.notifications)
    }

    /// Removes a notification from the local pending list.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    pub async fn remove_notification_from_list(
        &self,
        sequence_number: SequenceNumber,
    ) -> Result<()> {
        self.apdu
            .transmit(&NotificationSentRequest { sequence_number })
            .await
            .map(|_| ())
    }

    /// Sends ES9+.HandleNotification for a pending notification.
    ///
    /// # Errors
    ///
    /// Returns URL, HTTP, JSON, or RSP status errors.
    pub async fn handle_notification(
        &self,
        pending: &PendingNotification,
    ) -> Result<es9p::HandleNotificationResponse> {
        let address = parse_server_url(&pending.notification.address)?;
        let request = es9p::HandleNotificationRequest {
            pending_notification: pending.pending_notification.clone(),
        };
        let url = request.url(&address)?;
        self.send_json_checked(&url, &request).await
    }

    /// Cancels an RSP session locally and remotely.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, JSON, or card result errors.
    pub async fn cancel_session(
        &self,
        address: &Url,
        transaction_id: HexBytes,
        reason: CancelSessionReason,
    ) -> Result<es9p::CancelSessionResponse> {
        let card_response = self
            .apdu
            .transmit(&CancelSessionRequest {
                transaction_id: transaction_id.clone(),
                reason,
            })
            .await?;
        let request = es9p::CancelSessionRequest {
            transaction_id,
            cancel_session_response: card_response.response,
        };
        let url = request.url(address)?;
        self.send_json_checked(&url, &request).await
    }

    /// Lists profiles with optional ES10c search criteria and tag list.
    ///
    /// # Errors
    ///
    /// Returns APDU or decoding errors.
    pub async fn list_profiles(
        &self,
        search_criterion: Option<ProfileSearchCriterion>,
        tags: Vec<Tag>,
    ) -> Result<Vec<ProfileInfo>> {
        self.apdu
            .transmit(&ProfileInfoListRequest {
                search_criterion,
                tags,
            })
            .await
            .map(|response| response.profiles)
    }

    /// Enables a profile by ICCID or ISD-P AID.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    pub async fn enable_profile(&self, identifier: ProfileIdentifier, refresh: bool) -> Result<()> {
        self.profile_operation(ProfileOperation::Enable, identifier, refresh)
            .await
    }

    /// Disables a profile by ICCID or ISD-P AID.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    pub async fn disable_profile(
        &self,
        identifier: ProfileIdentifier,
        refresh: bool,
    ) -> Result<()> {
        self.profile_operation(ProfileOperation::Disable, identifier, refresh)
            .await
    }

    /// Deletes a profile by ICCID or ISD-P AID.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    pub async fn delete_profile(&self, identifier: ProfileIdentifier) -> Result<()> {
        self.profile_operation(ProfileOperation::Delete, identifier, false)
            .await
    }

    /// Resets eUICC memory using the common all-profile reset flags.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    pub async fn memory_reset(&self) -> Result<()> {
        self.apdu
            .transmit(&EuiccMemoryResetRequest {
                delete_operational_profiles: true,
                delete_field_loaded_test_profiles: true,
                reset_default_smdp_address: true,
            })
            .await
            .map(|_| ())
    }

    /// Reads the eUICC EID through ES10c.GetEID.
    ///
    /// # Errors
    ///
    /// Returns APDU or decoding errors.
    pub async fn eid(&self) -> Result<Vec<u8>> {
        self.apdu
            .transmit(&GetEuiccDataRequest)
            .await
            .map(|response| response.eid)
    }

    /// Sets a profile nickname.
    ///
    /// # Errors
    ///
    /// Returns validation, APDU, decoding, or card result errors.
    pub async fn set_nickname(&self, iccid: Iccid, nickname: &str) -> Result<()> {
        self.apdu
            .transmit(&SetNicknameRequest {
                iccid,
                nickname: nickname.to_owned(),
            })
            .await
            .map(|_| ())
    }

    /// Discovers downloadable profiles through ES11.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, JSON, or URL errors.
    pub async fn discovery(&self, address: &Url, imei: Imei) -> Result<Vec<es11::EventEntry>> {
        let initiate = self.initiate_authentication(address).await?;
        let authenticate_request = initiate.authenticate_server_request(imei, None);
        let card_response = self.apdu.transmit(&authenticate_request).await?;
        let request = es11::AuthenticateClientRequest {
            transaction_id: authenticate_request.transaction_id,
            authenticate_server_response: card_response.response,
        };
        let url = request.url(address)?;
        self.send_json_checked::<_, es11::AuthenticateClientResponse>(&url, &request)
            .await
            .map(|response| response.event_entries)
    }

    async fn send_json_checked<Request, Response>(
        &self,
        url: &Url,
        request: &Request,
    ) -> Result<Response>
    where
        Request: Serialize + Sync,
        Response: DeserializeOwned + Send + RspExecutionStatus,
    {
        let response = self.http.send_json(url, request).await?;
        check_rsp_status(&response)?;
        Ok(response)
    }

    async fn euicc_info(&self, version: EuiccInfoVersion) -> Result<Tlv> {
        self.apdu
            .transmit(&GetEuiccInfoRequest { version })
            .await
            .map(|response| response.response)
    }

    async fn profile_operation(
        &self,
        operation: ProfileOperation,
        identifier: ProfileIdentifier,
        refresh: bool,
    ) -> Result<()> {
        self.apdu
            .transmit(&ProfileOperationRequest {
                operation,
                identifier,
                refresh,
            })
            .await
            .map(|_| ())
    }
}
impl<T> Client<T, ReqwestJsonHttpClient>
where
    T: ApduTransmitter,
{
    /// Creates an LPA client with the default reqwest-backed HTTP transport.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Http`] when the default reqwest client cannot be
    /// built.
    ///
    /// # fn demo<T>(apdu: euicc::apdu::EuiccApdu<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// # {
    pub fn with_reqwest(apdu: EuiccApdu<T>) -> Result<Self> {
        Ok(Self::new(apdu, ReqwestJsonHttpClient::new()?))
    }

    /// Creates an LPA client with a caller-configured reqwest client.
    #[must_use]
    pub fn with_reqwest_client(apdu: EuiccApdu<T>, client: reqwest::Client) -> Self {
        Self::new(apdu, ReqwestJsonHttpClient::from_client(client))
    }
}
