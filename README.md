# runas

![crate](https://img.shields.io/crates/v/runas-rs.svg)
![docs](https://docs.rs/runas-rs/badge.svg)
![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-brightgreen)
[![Actions status](https://github.com/joaoviictorti/runas-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/joaoviictorti/runas-rs/actions)

An offensive version of `runas` in Rust with extra features. This crate provides support for spawning processes under different Windows user accounts, with privileges, secure token manipulation, profile/environment loading, and more.

## Getting Started

Add `runas-rs` to your project by updating your `Cargo.toml`:

```sh
cargo add runas-rs
```

## Example

Spawn a process under a different user account with fine-grained control over how the session is initialized. The following options can be combined to adjust the behavior of the spawned process:

```rs
use runas_rs::{Runas, Options};
use anyhow::Result;

fn main() -> Result<()> {
    let output = Runas::new("username", "password", Some("DOMAIN"))
        .options(Options::Env | Options::Profile)?
        .run("cmd.exe /c whoami")?;

    println!("Output: {}", output);
    Ok(())
}
```

For more information, including a more detailed overview of runas, [visit the documentation](https://docs.rs/runas-rs).

## References

I want to express my gratitude to these projects that inspired me to create `runas-rs` and contribute with some features:

- [Pavel - CreateProcessAsUser vs. CreateProcessWithTokenW](https://www.youtube.com/watch?v=y42BsQJhd5w&t=816s)
- [Pavel - Window Stations and Desktops](https://scorpiosoftware.net/2023/06/20/window-stations-and-desktops/)
- [RunasCs](https://github.com/antonioCoco/RunasCs)

## License

runas-rs is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/joaoviictorti/runas-rs/tree/main/LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](https://github.com/joaoviictorti/runas-rs/tree/main/LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in runas-rs by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
