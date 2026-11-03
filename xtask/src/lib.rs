// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod mount;

use anyhow::{Context, Result, bail};
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Output};

pub mod diff_walk;
pub use mount::{Mount, ReadOnly};

/// Calculate the SHA256 hash of the file at `path`.
///
/// This calculates the hash incrementally, so large files are not
/// loaded into memory all at once.
pub fn calc_file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn cmd_to_string(cmd: &Command) -> String {
    format!("{cmd:?}").replace('"', "")
}

/// Run a command.
///
/// Return an error if the command fails to launch or if it exits
/// non-zero.
pub fn run_cmd(cmd: &mut Command) -> Result<()> {
    eprintln!("run: {}", cmd_to_string(cmd));
    let program = cmd.get_program().to_string_lossy().into_owned();
    let status = cmd
        .status()
        .context(format!("failed to launch {program}"))?;
    if !status.success() {
        bail!("command {program} failed: {status:?}");
    }
    Ok(())
}

/// Run a command and capture its output.
///
/// Return an error if the command fails to launch or if it exits
/// non-zero.
pub fn capture_cmd(cmd: &mut Command) -> Result<Output> {
    eprintln!("capture: {}", cmd_to_string(cmd));
    let program = cmd.get_program().to_string_lossy().into_owned();
    let output = cmd
        .output()
        .context(format!("failed to launch {program}"))?;
    if !output.status.success() {
        bail!(
            "command {program} failed: {status:?}",
            status = output.status
        );
    }
    Ok(output)
}

/// Create a `Command` to run sudo.
pub fn sudo() -> Command {
    Command::new("sudo")
}

#[cfg(test)]
mod tests {
    use super::calc_file_sha256;
    use std::io::Write;

    #[test]
    fn test_calc_file_sha256() {
        for (contents, expected) in [
            (
                Vec::new(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".to_vec(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                vec![b'a'; 1_000_000],
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
        ] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(&contents).unwrap();
            assert_eq!(calc_file_sha256(file.path()).unwrap(), expected);
        }
    }
}
