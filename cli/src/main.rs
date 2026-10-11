//! Command-line interface for running a process with alternate Windows credentials.
//!
//! # Examples
//!
//! ```text
//! runas-rs -u username -p password -d DOMAIN -c "cmd.exe /c whoami" --profile
//! ```

use std::error::Error;

use clap::{ArgGroup, Parser};
use runas_rs::{Options, Runas};

/// Command-line arguments accepted by `runas-rs`.
#[derive(Parser, Debug)]
#[command(
    name = "runas-rs",
    about = "A runas implementation with extra features in Rust",
    version = "1.0",
    group(
        ArgGroup::new("auth_mode")
            .args(&["profile", "no_profile", "netonly"])
            .required(true)
            .multiple(false)
    )
)]
struct Args {
    /// Target account username.
    #[arg(short)]
    username: String,

    /// Password for the target account.
    #[arg(short)]
    password: String,

    /// Optional Windows domain containing the target account.
    #[arg(short = 'd', long)]
    domain: Option<String>,

    /// Command line executed with the supplied credentials.
    #[arg(short, long)]
    command: String,

    /// Pass the current process environment to the child process.
    #[arg(short)]
    env: bool,

    /// Load the target user's profile.
    #[arg(long)]
    profile: bool,

    /// Start without loading the target user's profile.
    #[arg(long = "noprofile")]
    no_profile: bool,

    /// Apply the supplied credentials only to outbound network access.
    #[arg(long)]
    netonly: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let mut options = Options::empty();

    if args.env {
        options |= Options::ENV;
    }
    if args.profile {
        options |= Options::PROFILE;
    }
    if args.no_profile {
        options |= Options::NO_PROFILE;
    }
    if args.netonly {
        options |= Options::NET_ONLY;
    }

    let mut runas = Runas::new(&args.username, &args.password, args.domain.as_deref())
        .options(options)?;

    match runas.run(&args.command) {
        Ok(output) => print!("{output}"),
        Err(e) => eprintln!("{e}"),
    }

    Ok(())
}
