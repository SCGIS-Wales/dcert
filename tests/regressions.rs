//! Regression tests for the audit quick fixes (plan PR 0.3).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use openssl::ssl::SslVersion;
use support::{ClientAuthMode, Identity, TEST_SERVER_CN, TlsServer, dcert_bin, json_output, test_data};

#[test]
fn starttls_with_a_bare_host_dials_the_host_not_a_url() {
    let server = TlsServer::builder().starttls_smtp().identity(Identity::Rsa).spawn();
    let output = dcert_bin()
        .args([
            &format!("127.0.0.1:{}", server.port()),
            "--starttls",
            "smtp",
            "--no-verify",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    assert_eq!(parsed["certificates"][0]["common_name"], TEST_SERVER_CN, "{parsed}");
}

#[test]
fn starttls_presents_the_configured_client_certificate() {
    let server = TlsServer::builder()
        .starttls_smtp()
        .versions(Some(SslVersion::TLS1_2), Some(SslVersion::TLS1_2))
        .client_auth(ClientAuthMode::Required)
        .spawn();
    let output = dcert_bin()
        .args([
            &format!("127.0.0.1:{}", server.port()),
            "--starttls",
            "smtp",
            "--no-verify",
            "--client-cert",
            test_data("verify-key-discovery/server.crt").to_str().unwrap(),
            "--client-key",
            test_data("verify-key-discovery/server.key").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    assert_eq!(parsed["connection"]["tls_version"], "TLSv1.2", "{parsed}");
    assert_eq!(parsed["connection"]["client_auth"], "presented", "{parsed}");
}

#[test]
fn export_pem_dash_puts_the_chain_in_json() {
    let output = dcert_bin()
        .args([
            test_data("valid.pem").to_str().unwrap(),
            "--export-pem",
            "-",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    assert!(
        parsed["pem_data"]
            .as_str()
            .is_some_and(|p| p.starts_with("-----BEGIN CERTIFICATE-----")),
        "{parsed}"
    );
}

#[test]
fn export_pem_dash_prints_the_chain_in_pretty_output() {
    let output = dcert_bin()
        .args([test_data("valid.pem").to_str().unwrap(), "--export-pem", "-"])
        .output()
        .expect("failed to run dcert");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.trim_end().ends_with("-----END CERTIFICATE-----"), "{stdout}");
}

#[test]
fn export_pem_to_a_file_keeps_json_stdout_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.pem");
    let output = dcert_bin()
        .args([
            test_data("valid.pem").to_str().unwrap(),
            "--export-pem",
            path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    assert!(parsed.get("pem_data").is_none(), "file export must not echo the PEM");
    assert!(path.exists());
}

#[test]
fn no_verify_warning_is_printed_once() {
    let server = TlsServer::builder().spawn();
    let output = dcert_bin()
        .args([&server.url(), "--no-verify", "--format", "json"])
        .output()
        .expect("failed to run dcert");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.matches("verification is disabled").count(), 1, "{stderr}");
}

#[test]
fn check_subcommand_and_separator_route_a_subcommand_named_target() {
    // `kb` is a dcert subcommand and a directory in this repository. After
    // `--` it must be read as a target, so the error names the file read.
    let output = dcert_bin()
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["check", "--format", "json", "--", "kb"])
        .output()
        .expect("failed to run dcert");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to read PEM file: kb"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn watch_mode_stops_cleanly_on_ctrl_c() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut child = dcert_bin()
        .args([test_data("valid.pem").to_str().unwrap(), "--watch", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcert --watch");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    while stdout.read_line(&mut line).expect("read") > 0 && !line.contains("Watch iteration 1") {
        line.clear();
    }
    // Let the first report finish so the loop is sleeping.
    std::thread::sleep(Duration::from_millis(500));
    let status = std::process::Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("kill -INT");
    assert!(status.success());

    let started = Instant::now();
    let exit = loop {
        if let Some(exit) = child.try_wait().expect("wait") {
            break exit;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "watch did not stop");
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut rest).expect("read rest");
    assert_eq!(exit.code(), Some(0), "cooperative stop exits 0");
    assert!(rest.contains("Watch stopped."), "{rest}");
}

// ---------------------------------------------------------------
// Plan PR 1.3: the CLI enforces the destination policy it is handed
// ---------------------------------------------------------------

#[test]
fn cli_refuses_a_loopback_target_when_private_destinations_are_denied() {
    let server = TlsServer::builder().spawn();
    let output = dcert_bin()
        .env("DCERT_DENY_PRIVATE_TARGETS", "1")
        .args([&server.url(), "--no-verify", "--format", "json"])
        .output()
        .expect("failed to run dcert");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("DCERT_DENY_PRIVATE_TARGETS"), "{stderr}");
}

#[test]
fn cli_allow_list_overrides_the_private_denial() {
    let server = TlsServer::builder().spawn();
    let output = dcert_bin()
        .env("DCERT_DENY_PRIVATE_TARGETS", "1")
        .env("DCERT_ALLOWED_TARGETS", "127.0.0.0/8")
        .args([&server.url(), "--no-verify", "--format", "json"])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    assert_eq!(parsed["certificates"][0]["common_name"], TEST_SERVER_CN, "{parsed}");
}

#[test]
fn cli_refuses_a_connect_to_override_outside_the_allow_list() {
    let server = TlsServer::builder().spawn();
    let output = dcert_bin()
        .env("DCERT_ALLOWED_TARGETS", "api.example.com")
        .args([
            "https://api.example.com",
            "--connect-to",
            &format!("api.example.com:443:127.0.0.1:{}", server.port()),
            "--no-verify",
        ])
        .output()
        .expect("failed to run dcert");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("DCERT_ALLOWED_TARGETS"), "{stderr}");
}

// ---------------------------------------------------------------
// Plan PR 1.5: secrets out of --help and argv
// ---------------------------------------------------------------

#[test]
fn help_never_prints_secret_environment_values() {
    for (subcommand, var) in [
        (vec!["check", "--help"], "DCERT_CERT_PASSWORD"),
        (vec!["check", "--help"], "DCERT_PROXY"),
        (vec!["vault", "--help"], "DCERT_LDAP_PASSWORD"),
        (vec!["vault", "--help"], "DCERT_APPROLE_SECRET_ID"),
    ] {
        let output = dcert_bin()
            .env(var, "hunter2-secret-value")
            .args(&subcommand)
            .output()
            .expect("failed to run dcert");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(var), "{var} should still be documented");
        assert!(!stdout.contains("hunter2-secret-value"), "{var} value leaked: {stdout}");
    }
}

#[test]
fn headers_file_headers_reach_the_server() {
    let server = TlsServer::builder()
        .respond(|req| {
            let mut out = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                req.len()
            )
            .into_bytes();
            out.extend_from_slice(req);
            out
        })
        .spawn();
    let dir = tempfile::tempdir().unwrap();
    let headers = dir.path().join("headers.txt");
    std::fs::write(&headers, "# comment\n\nX-Api-Key: from-file\nX-Second: two\n").unwrap();
    let output = dcert_bin()
        .args([
            &server.url(),
            "--no-verify",
            "--show-body",
            "--headers-file",
            headers.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run dcert");
    let parsed = json_output(&output);
    let body = parsed["connection"]["http_body_excerpt"]
        .as_str()
        .expect("echoed request");
    assert!(body.contains("\r\nX-Api-Key: from-file\r\n"), "{body:?}");
    assert!(body.contains("\r\nX-Second: two\r\n"), "{body:?}");
}

#[test]
fn malformed_headers_file_names_the_line_without_echoing_it() {
    let dir = tempfile::tempdir().unwrap();
    let headers = dir.path().join("headers.txt");
    std::fs::write(&headers, "Good: yes\nno-colon-secret-value\n").unwrap();
    let output = dcert_bin()
        .args(["https://example.invalid", "--headers-file", headers.to_str().unwrap()])
        .output()
        .expect("failed to run dcert");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("line 2"), "{stderr}");
    assert!(!stderr.contains("no-colon-secret-value"), "{stderr}");
}

#[test]
fn proxy_errors_mask_credentials() {
    let output = dcert_bin()
        .args(["https://example.invalid", "--proxy", "http://user:hunter2@[bad"])
        .output()
        .expect("failed to run dcert");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(!stderr.contains("hunter2"), "{stderr}");
}

// ---------------------------------------------------------------
// Plan PR 1.6: https:// proxies are refused rather than spoken to in plaintext
// ---------------------------------------------------------------

#[test]
fn https_proxy_flag_is_refused_with_a_clear_error() {
    let output = dcert_bin()
        .args(["https://example.invalid", "--proxy", "https://user:pw@proxy.corp:3128"])
        .output()
        .expect("failed to run dcert");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("not supported yet"), "{stderr}");
    assert!(!stderr.contains(":pw@"), "{stderr}");
}

#[test]
fn https_proxy_from_the_environment_gets_no_plaintext_connect() {
    use std::io::Read as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let output = dcert_bin()
        .env("HTTPS_PROXY", format!("https://127.0.0.1:{port}"))
        .args(["https://example.invalid", "--no-verify"])
        .output()
        .expect("failed to run dcert");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("not supported yet"), "{stderr}");
    if let Ok((mut stream, _)) = listener.accept() {
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        assert!(
            !String::from_utf8_lossy(&buf).contains("CONNECT"),
            "plaintext CONNECT was sent"
        );
    }
}
