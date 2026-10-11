//! # runas-rs
//!
//! A Rust library for running Windows processes with alternate user credentials.
//! It configures window station and desktop access, selects the appropriate
//! process creation API, and captures the child process output.
//!
//! ### Run as Another User
//!
//! Run a command with another user's credentials:
//!
//! ```no_run
//! use runas_rs::Runas;
//!
//! # fn main() -> anyhow::Result<()> {
//! let output = Runas::new("username", "password", Some("DOMAIN"))
//!     .run("cmd.exe /c whoami")?;
//!
//! println!("{output}");
//! # Ok(())
//! # }
//! ```
//!
//! ### Execution Options
//!
//! Combine execution options to control profile and environment loading:
//!
//! ```no_run
//! use runas_rs::{Options, Runas};
//!
//! # fn main() -> anyhow::Result<()> {
//! let output = Runas::new("username", "password", Some("DOMAIN"))
//!     .options(Options::ENV | Options::PROFILE)?
//!     .run("cmd.exe /c set")?;
//!
//! println!("{output}");
//! # Ok(())
//! # }
//! ```

#![allow(clippy::upper_case_acronyms)]
#![allow(non_upper_case_globals)]
#![doc(
    html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk-v2.png",
    html_favicon_url = "https://www.rust-lang.org/favicon.ico",
    html_root_url = "https://docs.rs/runas-rs/latest"
)]

mod acl;
mod pipe;
mod sid;
mod runas;

#[doc(inline)]
pub use runas::{Runas, Options};
