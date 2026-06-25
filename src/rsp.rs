//! SGP.22 remote server status and header types.

mod execution;
mod header;
mod status_code;

pub use execution::ExecutionStatus;
pub use header::Header;
pub use status_code::StatusCodeData;
