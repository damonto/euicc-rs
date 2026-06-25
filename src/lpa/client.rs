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
/// # Arguments
///
/// The generic `T` is an APDU transmitter and `H` is a JSON HTTP client.
///
/// # Returns
///
/// A high-level Local Profile Assistant facade.
///
/// # Errors
///
/// Construction does not fail; individual operations return APDU, JSON, or
/// protocol errors.
///
/// # Examples
///
/// ```no_run
/// # async fn demo<T, H>(
/// #     apdu: euicc::apdu::EuiccApdu<T>,
/// #     http: H,
/// # ) -> euicc::Result<()>
/// # where
/// #     T: uicc::apdu::ApduTransmitter,
/// #     H: euicc::lpa::JsonHttpClient,
/// # {
/// let client = euicc::lpa::Client::new(apdu, http);
/// let _challenge = client.euicc_challenge().await?;
/// # Ok(())
/// # }
/// ```
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
    ///
    /// # Arguments
    ///
    /// * `apdu` - ES10 APDU adapter.
    /// * `http` - ES9+/ES11 JSON HTTP client.
    ///
    /// # Returns
    ///
    /// A new [`Client`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn demo<T, H>(apdu: euicc::apdu::EuiccApdu<T>, http: H)
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _client = euicc::lpa::Client::new(apdu, http);
    /// # }
    /// ```
    #[must_use]
    pub const fn new(apdu: EuiccApdu<T>, http: H) -> Self {
        Self { apdu, http }
    }

    /// Returns the APDU adapter.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Shared reference to the APDU adapter.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn demo<T, H>(client: &euicc::lpa::Client<T, H>)
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _apdu = client.apdu();
    /// # }
    /// ```
    #[must_use]
    pub const fn apdu(&self) -> &EuiccApdu<T> {
        &self.apdu
    }

    /// Returns the JSON HTTP client.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Shared reference to the HTTP client.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn demo<T, H>(client: &euicc::lpa::Client<T, H>)
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _http = client.http();
    /// # }
    /// ```
    #[must_use]
    pub const fn http(&self) -> &H {
        &self.http
    }

    /// Closes the underlying APDU adapter.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the APDU adapter closes.
    ///
    /// # Errors
    ///
    /// Returns APDU close errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// client.close().await
    /// # }
    /// ```
    pub async fn close(&self) -> Result<()> {
        self.apdu.close().await
    }

    /// Reads ES10a.GetEuiccConfiguredAddresses.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Configured SM-DP+ and root SM-DS addresses.
    ///
    /// # Errors
    ///
    /// Returns APDU or response decoding errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _addresses = client.euicc_configured_addresses().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn euicc_configured_addresses(&self) -> Result<EuiccConfiguredAddressesResponse> {
        self.apdu.transmit(&EuiccConfiguredAddressesRequest).await
    }

    /// Sets ES10a.SetDefaultDpAddress.
    ///
    /// # Arguments
    ///
    /// * `address` - New default SM-DP+ address; an empty string clears it.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the card accepts the update.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// client.set_default_dp_address("smdp.example").await
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// 16-byte eUICC challenge.
    ///
    /// # Errors
    ///
    /// Returns APDU or response decoding errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let challenge = client.euicc_challenge().await?;
    /// assert_eq!(challenge.len(), 16);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn euicc_challenge(&self) -> Result<Vec<u8>> {
        self.apdu
            .transmit(&GetEuiccChallengeRequest)
            .await
            .map(|response| response.challenge)
    }

    /// Reads ES10b.GetEUICCInfo1.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Raw EUICCInfo1 TLV.
    ///
    /// # Errors
    ///
    /// Returns APDU or response decoding errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _info = client.euicc_info1().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn euicc_info1(&self) -> Result<Tlv> {
        self.euicc_info(EuiccInfoVersion::V1).await
    }

    /// Reads ES10b.GetEUICCInfo2.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Raw EUICCInfo2 TLV.
    ///
    /// # Errors
    ///
    /// Returns APDU or response decoding errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _info = client.euicc_info2().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn euicc_info2(&self) -> Result<Tlv> {
        self.euicc_info(EuiccInfoVersion::V2).await
    }

    /// Runs ES9+.InitiateAuthentication.
    ///
    /// # Arguments
    ///
    /// * `address` - SM-DP+ base URL.
    ///
    /// # Returns
    ///
    /// SM-DP+ authentication material.
    ///
    /// # Errors
    ///
    /// Returns APDU, URL, HTTP, or JSON errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     address: &url::Url,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _response = client.initiate_authentication(address).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `address` - SM-DP+ base URL.
    /// * `request` - ES10b.AuthenticateServer request.
    ///
    /// # Returns
    ///
    /// ES9+.AuthenticateClient response.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, JSON, or RSP status errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     address: &url::Url,
    /// #     request: &euicc::es10b::AuthenticateServerRequest,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _response = client.authenticate_client(address, request).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `address` - SM-DP+ base URL.
    /// * `request` - ES10b.PrepareDownload request.
    ///
    /// # Returns
    ///
    /// ES9+.GetBoundProfilePackage response containing the BPP.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, JSON, or RSP status errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     address: &url::Url,
    /// #     request: &euicc::es10b::PrepareDownloadRequest,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _response = client.prepare_download(address, request).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `response` - ES9+.GetBoundProfilePackage response.
    ///
    /// # Returns
    ///
    /// Final ES10b.LoadBoundProfilePackage response.
    ///
    /// # Errors
    ///
    /// Returns BPP validation, APDU transfer, TLV decoding, or card result
    /// errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     response: &euicc::es9p::GetBoundProfilePackageResponse,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _installed = client.install_bound_profile_package(response).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `activation_code` - Parsed activation code.
    /// * `imei` - Device IMEI.
    /// * `options` - Confirmation and progress callbacks.
    ///
    /// # Returns
    ///
    /// Final ES10b.LoadBoundProfilePackage response.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, profile metadata, cancellation, or installation
    /// errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     activation_code: &euicc::lpa::ActivationCode,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let imei = euicc::identifier::Imei::new("123456789012345")?;
    /// let _response = client
    ///     .download_profile(activation_code, imei, euicc::lpa::DownloadOptions::default())
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `filter` - Optional notification event filter.
    ///
    /// # Returns
    ///
    /// Notification metadata entries.
    ///
    /// # Errors
    ///
    /// Returns APDU or decoding errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _items = client.list_notifications(None).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `search_criterion` - Optional sequence number or event search.
    ///
    /// # Returns
    ///
    /// Pending notifications.
    ///
    /// # Errors
    ///
    /// Returns APDU or decoding errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _items = client.retrieve_notifications(None).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `sequence_number` - Sequence number that has been handled.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the eUICC removes the notification.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// client
    ///     .remove_notification_from_list(euicc::notification::SequenceNumber::new(1))
    ///     .await
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `pending` - Pending notification returned by ES10b.
    ///
    /// # Returns
    ///
    /// ES9+.HandleNotification response.
    ///
    /// # Errors
    ///
    /// Returns URL, HTTP, JSON, or RSP status errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     pending: &euicc::notification::PendingNotification,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _response = client.handle_notification(pending).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `address` - SM-DP+ base URL.
    /// * `transaction_id` - Transaction to cancel.
    /// * `reason` - SGP.22 cancellation reason.
    ///
    /// # Returns
    ///
    /// ES9+.CancelSession response.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, JSON, or card result errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     address: &url::Url,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _response = client
    ///     .cancel_session(
    ///         address,
    ///         euicc::identifier::HexBytes::from_bytes([0x01]),
    ///         euicc::es10b::CancelSessionReason::Postponed,
    ///     )
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `search_criterion` - Optional profile search criterion.
    /// * `tags` - Optional additional tag list.
    ///
    /// # Returns
    ///
    /// Matching profile metadata entries.
    ///
    /// # Errors
    ///
    /// Returns APDU or decoding errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _profiles = client.list_profiles(None, Vec::new()).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `identifier` - ICCID or ISD-P AID.
    /// * `refresh` - Whether REFRESH is requested.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the card enables the profile.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     id: euicc::es10c::ProfileIdentifier,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// client.enable_profile(id, true).await
    /// # }
    /// ```
    pub async fn enable_profile(&self, identifier: ProfileIdentifier, refresh: bool) -> Result<()> {
        self.profile_operation(ProfileOperation::Enable, identifier, refresh)
            .await
    }

    /// Disables a profile by ICCID or ISD-P AID.
    ///
    /// # Arguments
    ///
    /// * `identifier` - ICCID or ISD-P AID.
    /// * `refresh` - Whether REFRESH is requested.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the card disables the profile.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     id: euicc::es10c::ProfileIdentifier,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// client.disable_profile(id, true).await
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `identifier` - ICCID or ISD-P AID.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the card deletes the profile.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     id: euicc::es10c::ProfileIdentifier,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// client.delete_profile(id).await
    /// # }
    /// ```
    pub async fn delete_profile(&self, identifier: ProfileIdentifier) -> Result<()> {
        self.profile_operation(ProfileOperation::Delete, identifier, false)
            .await
    }

    /// Resets eUICC memory using the common all-profile reset flags.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the card accepts the reset.
    ///
    /// # Errors
    ///
    /// Returns APDU, decoding, or card result errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// client.memory_reset().await
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Raw EID bytes.
    ///
    /// # Errors
    ///
    /// Returns APDU or decoding errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(client: &euicc::lpa::Client<T, H>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let _eid = client.eid().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn eid(&self) -> Result<Vec<u8>> {
        self.apdu
            .transmit(&GetEuiccDataRequest)
            .await
            .map(|response| response.eid)
    }

    /// Sets a profile nickname.
    ///
    /// # Arguments
    ///
    /// * `iccid` - Profile ICCID.
    /// * `nickname` - New profile nickname.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the card accepts the nickname.
    ///
    /// # Errors
    ///
    /// Returns validation, APDU, decoding, or card result errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     iccid: euicc::identifier::Iccid,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// client.set_nickname(iccid, "work").await
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `address` - SM-DS base URL.
    /// * `imei` - Device IMEI.
    ///
    /// # Returns
    ///
    /// ES11 event entries.
    ///
    /// # Errors
    ///
    /// Returns APDU, HTTP, JSON, or URL errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo<T, H>(
    /// #     client: &euicc::lpa::Client<T, H>,
    /// #     address: &url::Url,
    /// # ) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// #     H: euicc::lpa::JsonHttpClient,
    /// # {
    /// let imei = euicc::identifier::Imei::new("123456789012345")?;
    /// let _events = client.discovery(address, imei).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Arguments
    ///
    /// * `apdu` - ES10 APDU adapter.
    ///
    /// # Returns
    ///
    /// A [`Client`] using [`ReqwestJsonHttpClient`] for ES9+/ES11 calls.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Http`] when the default reqwest client cannot be
    /// built.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn demo<T>(apdu: euicc::apdu::EuiccApdu<T>) -> euicc::Result<()>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// # {
    /// let _client = euicc::lpa::Client::with_reqwest(apdu)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_reqwest(apdu: EuiccApdu<T>) -> Result<Self> {
        Ok(Self::new(apdu, ReqwestJsonHttpClient::new()?))
    }

    /// Creates an LPA client with a caller-configured reqwest client.
    ///
    /// # Arguments
    ///
    /// * `apdu` - ES10 APDU adapter.
    /// * `client` - Reqwest client with custom TLS, proxy, timeout, or redirect
    ///   policy.
    ///
    /// # Returns
    ///
    /// A [`Client`] using the supplied reqwest client for ES9+/ES11 calls.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn demo<T>(apdu: euicc::apdu::EuiccApdu<T>) -> Result<(), reqwest::Error>
    /// # where
    /// #     T: uicc::apdu::ApduTransmitter,
    /// # {
    /// let http = reqwest::Client::builder().build()?;
    /// let _client = euicc::lpa::Client::with_reqwest_client(apdu, http);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_reqwest_client(apdu: EuiccApdu<T>, client: reqwest::Client) -> Self {
        Self::new(apdu, ReqwestJsonHttpClient::from_client(client))
    }
}
