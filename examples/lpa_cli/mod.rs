use std::error::Error;
use std::io;

use euicc::es10b::NotificationSearchCriterion;
use euicc::es10c::ProfileIdentifier;
use euicc::identifier::{Iccid, Imei};
use euicc::lpa::{ActivationCode, Client, DownloadOptions, DownloadStage, ReqwestJsonHttpClient};
use euicc::notification::{PendingNotification, SequenceNumber};
use euicc::profile::ProfileInfo;
use euicc::{EuiccError, Result};
use uicc::apdu::ApduTransmitter;
use url::Url;

pub(crate) type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExampleCommand {
    Help,
    Eid,
    Addresses,
    SetDefaultDp {
        address: String,
    },
    Profiles,
    ListNotifications,
    RetrieveNotifications {
        sequence: Option<SequenceNumber>,
    },
    HandleNotification {
        sequence: SequenceNumber,
    },
    RemoveNotification {
        sequence: SequenceNumber,
    },
    Enable {
        iccid: String,
        refresh: bool,
    },
    Disable {
        iccid: String,
        refresh: bool,
    },
    Delete {
        iccid: String,
    },
    Nickname {
        iccid: String,
        nickname: String,
    },
    Download {
        activation_code: String,
        imei: String,
        yes: bool,
        confirmation_code: Option<String>,
    },
    Discovery {
        address: String,
        imei: String,
    },
}

pub(crate) async fn run_command<T>(
    client: &Client<T, ReqwestJsonHttpClient>,
    command: ExampleCommand,
) -> Result<()>
where
    T: ApduTransmitter,
{
    match command {
        ExampleCommand::Help => Ok(()),
        ExampleCommand::Eid => {
            let eid = client.eid().await?;
            println!("EID: {}", hex_upper(&eid));
            Ok(())
        }
        ExampleCommand::Addresses => {
            let addresses = client.euicc_configured_addresses().await?;
            println!(
                "Default SM-DP+: {}",
                addresses.default_smdp_address.as_deref().unwrap_or("-")
            );
            println!("Root SM-DS: {}", addresses.root_smds_address);
            Ok(())
        }
        ExampleCommand::SetDefaultDp { address } => {
            client.set_default_dp_address(&address).await?;
            println!("Default SM-DP+ set to {address}");
            Ok(())
        }
        ExampleCommand::Profiles => {
            let profiles = client.list_profiles(None, &[]).await?;
            if profiles.is_empty() {
                println!("No profiles found");
                return Ok(());
            }
            for profile in &profiles {
                print_profile(profile);
            }
            Ok(())
        }
        ExampleCommand::ListNotifications => {
            let notifications = client.list_notifications(None).await?;
            if notifications.is_empty() {
                println!("No notification metadata found");
                return Ok(());
            }
            for notification in &notifications {
                println!(
                    "Sequence: {}, ICCID: {}, Operation: {:?}, Address: {}",
                    notification.sequence_number.value(),
                    optional_iccid(notification.iccid.as_ref()),
                    notification.operation,
                    notification.address
                );
            }
            Ok(())
        }
        ExampleCommand::RetrieveNotifications { sequence } => {
            let notifications = client
                .retrieve_notifications(sequence.map(NotificationSearchCriterion::SequenceNumber))
                .await?;
            if notifications.is_empty() {
                println!("No pending notifications found");
                return Ok(());
            }
            for pending in &notifications {
                print_pending_notification(pending);
            }
            Ok(())
        }
        ExampleCommand::HandleNotification { sequence } => {
            let pending = first_pending_notification(client, sequence).await?;
            client.handle_notification(&pending).await?;
            println!("Notification {} sent to SM-DP+", sequence.value());
            Ok(())
        }
        ExampleCommand::RemoveNotification { sequence } => {
            client.remove_notification_from_list(sequence).await?;
            println!("Notification {} removed from local list", sequence.value());
            Ok(())
        }
        ExampleCommand::Enable { iccid, refresh } => {
            client
                .enable_profile(ProfileIdentifier::Iccid(Iccid::new(&iccid)?), refresh)
                .await?;
            println!("Profile {iccid} enabled");
            Ok(())
        }
        ExampleCommand::Disable { iccid, refresh } => {
            client
                .disable_profile(ProfileIdentifier::Iccid(Iccid::new(&iccid)?), refresh)
                .await?;
            println!("Profile {iccid} disabled");
            Ok(())
        }
        ExampleCommand::Delete { iccid } => {
            client
                .delete_profile(ProfileIdentifier::Iccid(Iccid::new(&iccid)?))
                .await?;
            println!("Profile {iccid} deleted");
            Ok(())
        }
        ExampleCommand::Nickname { iccid, nickname } => {
            client.set_nickname(Iccid::new(&iccid)?, &nickname).await?;
            println!("Profile {iccid} nickname set to {nickname}");
            Ok(())
        }
        ExampleCommand::Download {
            activation_code,
            imei,
            yes,
            confirmation_code,
        } => {
            if !yes {
                return Err(EuiccError::Canceled);
            }
            let activation_code = ActivationCode::from_text(&activation_code)?;
            let imei = Imei::new(&imei)?;
            let progress = |stage: DownloadStage| println!("Download stage: {}", stage.as_str());
            let confirm = |metadata: &ProfileInfo| {
                println!("Confirming profile download:");
                print_profile(metadata);
                true
            };
            let options = DownloadOptions {
                confirmation_code: confirmation_code.as_deref(),
                confirm_profile: Some(&confirm),
                request_confirmation_code: None,
                progress: Some(&progress),
            };
            let install = client
                .download_profile(&activation_code, imei, options)
                .await?;
            if let Some(aid) = install.isdp_aid() {
                println!("Installed ISD-P AID: {}", hex_upper(aid.as_bytes()));
            }
            println!(
                "Install notification sequence: {}",
                install.notification.sequence_number.value()
            );
            Ok(())
        }
        ExampleCommand::Discovery { address, imei } => {
            let address = parse_url(&address)?;
            let imei = Imei::new(&imei)?;
            let entries = client.discovery(&address, imei).await?;
            if entries.is_empty() {
                println!("No discovery events found");
                return Ok(());
            }
            for entry in &entries {
                println!(
                    "Discovered event: {}, RSP server: {}",
                    entry.event_id, entry.rsp_server_address
                );
            }
            Ok(())
        }
    }
}

pub(crate) fn parse_command(command: &str, args: Vec<String>) -> ExampleResult<ExampleCommand> {
    match command {
        "eid" => {
            expect_no_args(command, &args)?;
            Ok(ExampleCommand::Eid)
        }
        "addresses" => {
            expect_no_args(command, &args)?;
            Ok(ExampleCommand::Addresses)
        }
        "set-default-dp" => Ok(ExampleCommand::SetDefaultDp {
            address: only_arg(command, args, "fqdn")?,
        }),
        "profiles" => {
            expect_no_args(command, &args)?;
            Ok(ExampleCommand::Profiles)
        }
        "notifications" | "list-notifications" => {
            expect_no_args(command, &args)?;
            Ok(ExampleCommand::ListNotifications)
        }
        "retrieve-notifications" => {
            let sequence = match args.as_slice() {
                [] => None,
                [value] => Some(parse_sequence(value)?),
                _ => {
                    return Err(input_error(
                        "retrieve-notifications accepts at most one sequence",
                    ));
                }
            };
            Ok(ExampleCommand::RetrieveNotifications { sequence })
        }
        "handle-notification" => Ok(ExampleCommand::HandleNotification {
            sequence: parse_sequence(&only_arg(command, args, "sequence")?)?,
        }),
        "remove-notification" => Ok(ExampleCommand::RemoveNotification {
            sequence: parse_sequence(&only_arg(command, args, "sequence")?)?,
        }),
        "enable" => {
            let (iccid, refresh) = parse_profile_operation_args(command, args)?;
            Ok(ExampleCommand::Enable { iccid, refresh })
        }
        "disable" => {
            let (iccid, refresh) = parse_profile_operation_args(command, args)?;
            Ok(ExampleCommand::Disable { iccid, refresh })
        }
        "delete" => Ok(ExampleCommand::Delete {
            iccid: only_arg(command, args, "iccid")?,
        }),
        "nickname" => {
            if args.len() != 2 {
                return Err(input_error("nickname requires iccid and nickname"));
            }
            Ok(ExampleCommand::Nickname {
                iccid: args[0].clone(),
                nickname: args[1].clone(),
            })
        }
        "download" => parse_download_args(args),
        "discovery" => {
            if args.len() != 2 {
                return Err(input_error("discovery requires smds-url and imei"));
            }
            Ok(ExampleCommand::Discovery {
                address: args[0].clone(),
                imei: args[1].clone(),
            })
        }
        "-h" | "--help" | "help" => Ok(ExampleCommand::Help),
        _ => Err(input_error("unknown command")),
    }
}

pub(crate) fn next_required_arg(
    args: &mut impl Iterator<Item = String>,
    name: &'static str,
) -> ExampleResult<String> {
    args.next()
        .ok_or_else(|| input_error(&format!("missing {name}")))
}

pub(crate) fn input_error(message: &str) -> Box<dyn Error> {
    Box::new(io::Error::new(
        io::ErrorKind::InvalidInput,
        message.to_owned(),
    ))
}

pub(crate) fn print_command_usage() {
    println!(
        "Commands:
  eid
  addresses
  set-default-dp <fqdn>
  profiles
  notifications
  retrieve-notifications [sequence]
  handle-notification <sequence>
  remove-notification <sequence>
  enable <iccid> [--no-refresh]
  disable <iccid> [--no-refresh]
  delete <iccid>
  nickname <iccid> <nickname>
  discovery <smds-url> <imei>
  download <activation-code> <imei> --yes [--confirmation-code CODE]"
    );
}

async fn first_pending_notification<T>(
    client: &Client<T, ReqwestJsonHttpClient>,
    sequence: SequenceNumber,
) -> Result<PendingNotification>
where
    T: ApduTransmitter,
{
    let mut notifications = client
        .retrieve_notifications(Some(NotificationSearchCriterion::SequenceNumber(sequence)))
        .await?;
    if notifications.is_empty() {
        return Err(EuiccError::MissingField("pendingNotification"));
    }
    Ok(notifications.remove(0))
}

fn parse_download_args(args: Vec<String>) -> ExampleResult<ExampleCommand> {
    if args.len() < 2 {
        return Err(input_error("download requires activation-code and imei"));
    }
    let activation_code = args[0].clone();
    let imei = args[1].clone();
    let mut yes = false;
    let mut confirmation_code = None;
    let mut index = 2usize;
    while index < args.len() {
        match args[index].as_str() {
            "--yes" => {
                yes = true;
                index += 1;
            }
            "--confirmation-code" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(input_error("--confirmation-code requires a value"));
                };
                confirmation_code = Some(value.clone());
                index += 2;
            }
            _ => return Err(input_error("unknown download option")),
        }
    }
    Ok(ExampleCommand::Download {
        activation_code,
        imei,
        yes,
        confirmation_code,
    })
}

fn parse_profile_operation_args(command: &str, args: Vec<String>) -> ExampleResult<(String, bool)> {
    if args.is_empty() {
        return Err(input_error("profile operation requires iccid"));
    }
    let iccid = args[0].clone();
    let mut refresh = true;
    for arg in &args[1..] {
        if arg == "--no-refresh" {
            refresh = false;
            continue;
        }
        return Err(input_error(&format!(
            "{command} received an unknown option"
        )));
    }
    Ok((iccid, refresh))
}

fn only_arg(command: &str, args: Vec<String>, name: &'static str) -> ExampleResult<String> {
    if args.len() != 1 {
        return Err(input_error(&format!("{command} requires {name}")));
    }
    Ok(args[0].clone())
}

fn expect_no_args(command: &str, args: &[String]) -> ExampleResult<()> {
    if args.is_empty() {
        return Ok(());
    }
    Err(input_error(&format!("{command} does not accept arguments")))
}

fn parse_sequence(value: &str) -> ExampleResult<SequenceNumber> {
    let sequence = value
        .parse::<i64>()
        .map_err(|error| input_error(&format!("invalid sequence number: {error}")))?;
    Ok(SequenceNumber::new(sequence))
}

fn parse_url(value: &str) -> Result<Url> {
    let text = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    Url::parse(&text).map_err(|error| EuiccError::Url(error.to_string()))
}

fn print_profile(profile: &ProfileInfo) {
    println!(
        "Profile: {}, ICCID: {}, AID: {}, State: {:?}, Class: {:?}",
        profile.profile_name.as_deref().unwrap_or("-"),
        optional_iccid(profile.iccid.as_ref()),
        profile
            .isdp_aid
            .as_ref()
            .map(|aid| hex_upper(aid.as_bytes()))
            .unwrap_or_else(|| "-".to_owned()),
        profile.state,
        profile.class
    );
}

fn print_pending_notification(pending: &PendingNotification) {
    println!(
        "Sequence: {}, ICCID: {}, Operation: {:?}, Address: {}",
        pending.notification.sequence_number.value(),
        optional_iccid(pending.notification.iccid.as_ref()),
        pending.notification.operation,
        pending.notification.address
    );
}

fn optional_iccid(iccid: Option<&Iccid>) -> String {
    iccid
        .map(ToString::to_string)
        .unwrap_or_else(|| "-".to_owned())
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}
