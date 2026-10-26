//! Every network path ends within the probe budget (plan PR 2.1). Each
//! server below drips one byte every 200 ms, so no single read ever times
//! out; only the wall clock deadline can end the exchange.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::time::{Duration, Instant};
use support::{TlsServer, dcert_bin, spawn_drip_server};

const DRIP: Duration = Duration::from_millis(200);
/// --timeout 1 plus --read-timeout 1, with slack for a loaded CI runner.
const LIMIT: Duration = Duration::from_secs(8);

fn run(args: &[&str]) -> (std::process::Output, Duration) {
    let started = Instant::now();
    let output = dcert_bin()
        .args(args)
        .args(["--timeout", "1", "--read-timeout", "1"])
        .output()
        .expect("failed to run dcert");
    (output, started.elapsed())
}

#[test]
fn a_dripped_handshake_ends_at_the_deadline_and_says_timeout() {
    // A TLS record header announcing 16 KiB, then the body a byte at a time.
    let port = spawn_drip_server(b"\x16\x03\x03\x40\x00\x02", b'A', DRIP);
    let (output, elapsed) = run(&[&format!("https://127.0.0.1:{port}"), "--no-verify"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(elapsed < LIMIT, "took {elapsed:?}: {stderr}");
    assert!(!output.status.success());
    assert!(stderr.contains("timed out during the TLS handshake"), "{stderr}");
}

#[test]
fn a_dripped_starttls_banner_ends_at_the_deadline() {
    let port = spawn_drip_server(b"220-", b'A', DRIP);
    let (output, elapsed) = run(&[&format!("127.0.0.1:{port}"), "--starttls", "smtp", "--no-verify"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(elapsed < LIMIT, "took {elapsed:?}: {stderr}");
    assert!(stderr.contains("timed out during the STARTTLS exchange"), "{stderr}");
}

#[test]
fn a_silent_starttls_server_is_reported_as_a_timeout_not_a_parse_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let held = listener.accept();
        std::thread::sleep(Duration::from_secs(10));
        drop(held);
    });
    let (output, elapsed) = run(&[&format!("127.0.0.1:{port}"), "--starttls", "smtp"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(elapsed < LIMIT, "took {elapsed:?}");
    assert!(stderr.contains("timed out"), "{stderr}");
    assert!(!stderr.contains("unexpected banner"), "{stderr}");
}

#[test]
fn an_overlong_starttls_reply_is_refused() {
    static LINES: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| "250-filler\r\n".repeat(70).into_bytes());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        use std::io::Write;
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(&LINES);
            std::thread::sleep(Duration::from_secs(3));
        }
    });
    let (output, _) = run(&[&format!("127.0.0.1:{port}"), "--starttls", "smtp"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("exceeds 64 lines"), "{stderr}");
}

#[test]
fn a_dripped_http_response_ends_within_the_budget() {
    let server = TlsServer::builder()
        .drip(DRIP)
        .respond(|_| {
            let mut head = b"HTTP/1.1 200 OK\r\nX-Slow: ".to_vec();
            head.extend(std::iter::repeat_n(b'A', 400));
            head
        })
        .spawn();
    let (output, elapsed) = run(&[&server.url(), "--no-verify", "--format", "json"]);
    assert!(
        elapsed < LIMIT,
        "took {elapsed:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_dripped_proxy_connect_answer_ends_within_the_budget() {
    let proxy = spawn_drip_server(b"HTTP/1.1 200 Connection established\r\nX: ", b'A', DRIP);
    let (output, elapsed) = run(&[
        "https://example.invalid",
        "--proxy",
        &format!("http://127.0.0.1:{proxy}"),
        "--no-verify",
    ]);
    assert!(
        elapsed < LIMIT,
        "took {elapsed:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success());
}
