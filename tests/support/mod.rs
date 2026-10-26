//! Helpers shared by every integration test crate.
//!
//! The loopback TLS harness lives in `src/testutil.rs` so unit tests and
//! integration tests use one implementation; it is included here by path.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "../../src/testutil.rs"]
mod testutil;

// Not every test crate uses the TLS harness.
#[allow(unused_imports)]
pub use testutil::*;

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// Proxy variables dcert honours. They are removed from every child so a
/// developer's or CI runner's proxy can never reach a loopback test.
const PROXY_ENV: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "DCERT_PROXY",
    "DCERT_NOPROXY",
];

/// The `dcert` binary under test, with proxy settings stripped.
pub fn dcert_bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dcert"));
    for var in PROXY_ENV {
        cmd.env_remove(var);
    }
    cmd
}

/// Run dcert with `args`, feed `input` on stdin and wait for it to finish.
pub fn run_with_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = dcert_bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcert");
    child
        .stdin
        .take()
        .expect("stdin handle")
        .write_all(input)
        .expect("failed to write stdin");
    child.wait_with_output().expect("failed to wait")
}

/// Parse dcert's JSON output, failing the test with both streams otherwise.
pub fn json_output(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "expected JSON output ({e}); stdout: {stdout}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// `OPENSSL_VERSION_NUMBER` of the linked library, as the tests see it.
pub fn openssl_number() -> i64 {
    openssl::version::number()
}
