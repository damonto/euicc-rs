use std::env;
use std::error::Error;

use euicc::apdu::EuiccApdu;
use euicc::lpa::Client;

#[path = "lpa_cli/mod.rs"]
mod lpa_cli;

use lpa_cli::{ExampleCommand, ExampleResult};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn Error>> {
    let cli = parse_cli()?;
    if matches!(cli.command, ExampleCommand::Help) {
        print_usage();
        return Ok(());
    }

    let readers = uicc::ccid::list_readers().await?;
    let reader_name = select_reader(&readers, cli.reader.as_deref())?;
    println!("Using reader: {reader_name}");

    let reader = uicc::ccid::open(reader_name).await?;
    let apdu = EuiccApdu::open(reader, 254).await?;
    let client = Client::with_reqwest(apdu)?;
    let command_result = lpa_cli::run_command(&client, cli.command).await;
    let close_result = client.close().await;
    command_result?;
    close_result?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    reader: Option<String>,
    command: ExampleCommand,
}

fn parse_cli() -> ExampleResult<Cli> {
    let mut args = env::args().skip(1);
    let mut reader = None;

    loop {
        let Some(arg) = args.next() else {
            return Ok(Cli {
                reader,
                command: ExampleCommand::Help,
            });
        };
        match arg.as_str() {
            "--reader" => {
                reader = Some(lpa_cli::next_required_arg(&mut args, "--reader value")?);
            }
            "-h" | "--help" => {
                return Ok(Cli {
                    reader,
                    command: ExampleCommand::Help,
                });
            }
            command => {
                let rest = args.collect::<Vec<_>>();
                return Ok(Cli {
                    reader,
                    command: lpa_cli::parse_command(command, rest)?,
                });
            }
        }
    }
}

fn select_reader<'a>(readers: &'a [String], requested: Option<&str>) -> ExampleResult<&'a str> {
    if let Some(requested) = requested {
        if let Some(reader) = readers.iter().find(|reader| reader.as_str() == requested) {
            return Ok(reader.as_str());
        }
        return Err(lpa_cli::input_error("requested reader was not found"));
    }
    readers
        .first()
        .map(String::as_str)
        .ok_or_else(|| lpa_cli::input_error("no PC/SC readers found"))
}

fn print_usage() {
    println!(
        "Usage:
  cargo run --example ccid_lpa --features ccid -- [--reader NAME] <command>

CCID options:
  --reader NAME"
    );
    println!();
    lpa_cli::print_command_usage();
    println!(
        "
Examples:
  cargo run --example ccid_lpa --features ccid -- eid
  cargo run --example ccid_lpa --features ccid -- profiles
  cargo run --example ccid_lpa --features ccid -- discovery lpa.ds.gsma.com 356938035643809
  cargo run --example ccid_lpa --features ccid -- download 'LPA:1$smdp.example$MATCH' 356938035643809 --yes"
    );
}
