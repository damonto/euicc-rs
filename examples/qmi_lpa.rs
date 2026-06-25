use std::env;
use std::error::Error;

use euicc::apdu::EuiccApdu;
use euicc::lpa::Client;
use uicc::qcom::qmi::{DirectDialer, ProxyDialer};

#[path = "lpa_cli/mod.rs"]
mod lpa_cli;

use lpa_cli::{ExampleCommand, ExampleResult};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    device: String,
    slot: u8,
    transport: QmiTransport,
    command: ExampleCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QmiTransport {
    Proxy { address: Option<String> },
    Direct,
}

impl QmiTransport {
    const fn name(&self) -> &'static str {
        match self {
            Self::Proxy { .. } => "qmi-proxy",
            Self::Direct => "direct cdc-wdm",
        }
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn Error>> {
    let cli = parse_cli()?;
    if matches!(cli.command, ExampleCommand::Help) {
        print_usage();
        return Ok(());
    }

    let Cli {
        device,
        slot,
        transport,
        command,
    } = cli;
    println!(
        "Using QMI device: {device}, slot: {slot}, transport: {}",
        transport.name()
    );

    match transport {
        QmiTransport::Proxy { address } => {
            let mut dialer = ProxyDialer::new(device);
            if let Some(address) = address {
                dialer = dialer.with_address(proxy_address(&address));
            }
            let transport = uicc::qcom::qmi::open(dialer).await?;
            run_with_transport(transport, slot, command).await?;
        }
        QmiTransport::Direct => {
            let transport = uicc::qcom::qmi::open(DirectDialer::new(device)).await?;
            run_with_transport(transport, slot, command).await?;
        }
    }

    Ok(())
}

async fn run_with_transport<T>(
    transport: T,
    slot: u8,
    command: ExampleCommand,
) -> std::result::Result<(), Box<dyn Error>>
where
    T: uicc::qcom::Transport,
{
    let reader = uicc::qcom::uim::Reader::new(transport, slot, 0).await?;
    let apdu = EuiccApdu::open_qcom(reader, 254).await?;
    let client = Client::with_reqwest(apdu)?;
    let command_result = lpa_cli::run_command(&client, command).await;
    let close_result = client.close().await;
    command_result?;
    close_result?;
    Ok(())
}

fn parse_cli() -> ExampleResult<Cli> {
    let mut args = env::args().skip(1);
    let mut device = "/dev/cdc-wdm0".to_owned();
    let mut slot = 1u8;
    let mut direct = false;
    let mut proxy_address = None;

    loop {
        let Some(arg) = args.next() else {
            return Ok(Cli {
                device,
                slot,
                transport: transport_from_options(direct, proxy_address)?,
                command: ExampleCommand::Help,
            });
        };
        match arg.as_str() {
            "--device" => {
                device = lpa_cli::next_required_arg(&mut args, "--device value")?;
            }
            "--slot" => {
                let value = lpa_cli::next_required_arg(&mut args, "--slot value")?;
                slot = parse_slot(&value)?;
            }
            "--proxy" => {
                direct = false;
            }
            "--proxy-address" => {
                proxy_address = Some(lpa_cli::next_required_arg(
                    &mut args,
                    "--proxy-address value",
                )?);
            }
            "--direct" => {
                direct = true;
            }
            "-h" | "--help" => {
                return Ok(Cli {
                    device,
                    slot,
                    transport: transport_from_options(direct, proxy_address)?,
                    command: ExampleCommand::Help,
                });
            }
            command => {
                let rest = args.collect::<Vec<_>>();
                return Ok(Cli {
                    device,
                    slot,
                    transport: transport_from_options(direct, proxy_address)?,
                    command: lpa_cli::parse_command(command, rest)?,
                });
            }
        }
    }
}

fn transport_from_options(
    direct: bool,
    proxy_address: Option<String>,
) -> ExampleResult<QmiTransport> {
    if direct {
        if proxy_address.is_some() {
            return Err(lpa_cli::input_error(
                "--proxy-address cannot be used with --direct",
            ));
        }
        return Ok(QmiTransport::Direct);
    }
    Ok(QmiTransport::Proxy {
        address: proxy_address,
    })
}

fn parse_slot(value: &str) -> ExampleResult<u8> {
    let slot = value
        .parse::<u8>()
        .map_err(|error| lpa_cli::input_error(&format!("invalid slot: {error}")))?;
    if !(1..=5).contains(&slot) {
        return Err(lpa_cli::input_error("slot must be in the 1..=5 range"));
    }
    Ok(slot)
}

fn proxy_address(value: &str) -> String {
    if let Some(name) = value.strip_prefix('@') {
        format!("\0{name}")
    } else {
        value.to_owned()
    }
}

fn print_usage() {
    println!(
        "Usage:
  cargo run --example qmi_lpa --features qmi-linux -- [--device PATH] [--slot N] [--direct] <command>

QMI options:
  --device PATH            cdc-wdm device passed to QMI, default: /dev/cdc-wdm0
  --slot N                 one-based UIM slot number, default: 1
  --proxy                  use qmi-proxy, default
  --proxy-address ADDRESS  qmi-proxy socket path; @name means Linux abstract socket
  --direct                 open the cdc-wdm device directly"
    );
    println!();
    lpa_cli::print_command_usage();
    println!(
        "
Examples:
  cargo run --example qmi_lpa --features qmi-linux -- eid
  cargo run --example qmi_lpa --features qmi-linux -- --device /dev/cdc-wdm1 --slot 2 profiles
  cargo run --example qmi_lpa --features qmi-linux -- --direct eid
  cargo run --example qmi_lpa --features qmi-linux -- discovery lpa.ds.gsma.com 356938035643809
  cargo run --example qmi_lpa --features qmi-linux -- download 'LPA:1$smdp.example$MATCH' 356938035643809 --yes"
    );
}
