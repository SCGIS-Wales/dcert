# Changelog

All notable changes to dcert are recorded here. Every merge to `main` is a
release; entries collect under `Unreleased` until the next minor release
summary is written.

## Unreleased

### CI

- The main test job runs `cargo test` and `cargo clippy --all-targets` without
  `--all-features`, so the system OpenSSL code path that ships is tested; the
  vendored OpenSSL job is unchanged.
- New jobs: MSRV check on Rust 1.91, `pip-audit` for the Python package, and
  the ubuntu 22.04 built binary probing an ML-KEM loopback server inside
  `debian:trixie` (allowed to fail until plan PR 2.6).
- Every GitHub Action is pinned to a commit SHA.

### Testing

- Hermetic TLS test harness shared by unit and integration tests
  (`src/testutil.rs`, included by `tests/support/mod.rs`). A builder pins
  protocol versions, TLS 1.2 ciphers, TLS 1.3 suites, groups, security level,
  client authentication, ALPN and the server identity. RSA and ECDSA P-256
  test identities and a test CA are generated in memory.
- Integration tests strip every proxy variable (`HTTPS_PROXY`, `HTTP_PROXY`,
  `ALL_PROXY`, `NO_PROXY` in both cases, `DCERT_PROXY`, `DCERT_NOPROXY`) from
  the dcert child, so a runner's proxy can never reach a loopback test.
