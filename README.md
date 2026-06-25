# euicc-rs

Rust implementation of GSMA SGP.22 eUICC profile-management primitives.

The crate follows the SGP.22 interface boundaries and keeps the public API
typed around BER-TLV values, ES9+ HTTPS messages, ES10 card commands, ES11
event messages, profile metadata, notifications, and LPA orchestration. Card
I/O is provided by [`uicc-rs`](https://github.com/damonto/uicc-rs), so the same
high-level LPA client can run over PC/SC CCID readers or modem QMI UIM access.

This project is still developed as a protocol crate, not a polished end-user
LPA. The examples are real-device smoke tools that mirror the workflows used
while validating the implementation.

## Protocol Modules

- `es9p`: ES9+ HTTPS request and response models.
- `es10a`: ES10a eUICC configuration commands.
- `es10b`: ES10b download, notification, and authentication commands.
- `es10c`: ES10c local profile operations.
- `es11`: ES11 event and authentication messages.
- `apdu`: ISD-R APDU adapter, STORE DATA segmentation, and GET RESPONSE loops.
- `lpa`: high-level LPA client and reqwest-backed JSON HTTP client.
- `profile`, `notification`, `identifier`, `rsp`, `bertlv`: typed support
  models shared by the ES modules.

## Requirements

- Rust `1.96` or newer.
- Linux for `qmi-linux`, `mbim-linux`, and `qrtr-linux` transports.
- PC/SC and a supported reader for the `ccid` example.
- `qmi-proxy` for the default QMI example transport, or `--direct` for direct
  cdc-wdm access.
- Network access for ES9+/ES11 server calls such as discovery and profile
  download.

## Feature Flags

| Feature | Enables |
| --- | --- |
| `ccid` | PC/SC CCID reader support through `uicc-rs`. |
| `at` | AT/CSIM transport support through `uicc-rs`. |
| `mbim-linux` | Linux MBIM support through `uicc-rs`. |
| `qmi-linux` | Linux QMI cdc-wdm and qmi-proxy support through `uicc-rs`. |
| `qrtr-linux` | Linux AF_QIPCRTR QMI support through `uicc-rs`. |

The default feature set is empty. Enable only the transports needed by the
caller or example.

## Build And Test

```bash
cargo build
cargo test
cargo fmt --check
cargo clippy --all-features --all-targets -- -D warnings
```

Build all real-device examples:

```bash
cargo build --all-features --examples
```

## Real-Device Examples

The examples use the shared command set in `examples/lpa_cli`:

```text
eid
addresses
set-default-dp <fqdn>
profiles
notifications
retrieve-notifications [sequence]
handle-notification <sequence>
remove-notification <sequence>
enable <iccid> [--refresh]
disable <iccid> [--refresh]
delete <iccid>
nickname <iccid> <nickname>
discovery <smds-address> <imei>
download <activation-code> <imei> [--confirmation-code value] --yes
```

### QMI

Default qmi-proxy transport:

```bash
sudo -E cargo run --example qmi_lpa --features qmi-linux -- \
  --device /dev/cdc-wdm2 --slot 1 profiles
```

Direct cdc-wdm transport:

```bash
sudo -E cargo run --example qmi_lpa --features qmi-linux -- \
  --device /dev/cdc-wdm2 --slot 1 --direct eid
```

Discovery and download:

```bash
sudo -E cargo run --example qmi_lpa --features qmi-linux -- \
  --device /dev/cdc-wdm2 --slot 1 discovery lpa.ds.gsma.com 356938035643809

sudo -E cargo run --example qmi_lpa --features qmi-linux -- \
  --device /dev/cdc-wdm2 --slot 1 download 'LPA:1$smdp.example$MATCH' \
  356938035643809 --yes
```

### CCID

Use the first PC/SC reader:

```bash
cargo run --example ccid_lpa --features ccid -- profiles
```

Use an explicit reader name:

```bash
cargo run --example ccid_lpa --features ccid -- --reader "Reader Name" eid
```

## HTTP Client

`lpa::Client::with_reqwest` builds a default Rustls-backed reqwest client.
Callers that need proxy, timeout, root-store, or tracing policy control can
provide their own `reqwest::Client` with `Client::with_reqwest_client`, or
implement `lpa::JsonHttpClient` for a custom HTTP stack.

## Validation Notes

The implementation is cross-checked against `euicc-go` behavior where useful
and against SGP.22 wire boundaries where the specification is authoritative.
The repository keeps `Cargo.lock` committed so examples and hardware smoke
tests resolve the same `uicc-rs` Git dependency revision.
