//! SGP.22 eUICC profile-management protocol primitives.
//!
//! The crate mirrors the SGP.22 interface boundaries while keeping the Rust API
//! explicit: BER-TLV values are typed, card commands return typed responses,
//! and byte-oriented identifiers are newtypes rather than loose `Vec<u8>`
//! values.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod apdu;
pub mod bertlv;
pub mod bpp;
pub mod error;
pub mod es10a;
pub mod es10b;
pub mod es10c;
pub mod es11;
pub mod es9p;
pub mod identifier;
pub mod lpa;
pub mod notification;
pub mod primitive;
pub mod profile;
pub mod rsp;

mod rootci;

pub use error::{EuiccError, Result};
