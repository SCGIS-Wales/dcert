# Changelog

All notable changes to dcert are recorded here. Every merge to `main` is a
release; entries collect under `Unreleased` until the next minor release
summary is written.

## Unreleased

### Security

- MCP file root confinement (`DCERT_MCP_FILE_ROOT`): a relative path could
  escape the root because it was validated against the root but resolved by
  the child against the server's working directory. Tools now pass the
  canonical absolute path to the child, and the child runs in the first
  root. Probe targets that name a local file are confined as well, and the
  refusal no longer reveals whether a file outside the roots exists.
- The system temp directory is no longer a default file root (it is world
  writable); the default is the working directory only. Set
  `DCERT_MCP_FILE_ROOT` to add it back.

### Fixed

- `--starttls` with a bare host (`mail.example.com:587`) dialled the
  `https://` URL the target parser had added; the scheme is now stripped and
  IPv6 literals in brackets are understood. STARTTLS probes also present the
  configured client certificate and report `client_auth: presented`.
- `--export-pem -` includes the chain in the output (`pem_data` in JSON and
  YAML, appended in pretty output). The MCP `export_pem` tool uses it, so a
  call without `output_path` now returns the PEM. The file export
  confirmation moved to stderr so JSON on stdout stays valid.
- MCP `explain_edge_term` treats the CLI's "nothing matched" exit code (2,
  with an empty list) as an answer rather than a failure.
- MCP `create_truststore` refuses leaf certificates by default
  (`allow_non_ca: false`), matching the CLI. The Python
  `create_truststore()` gains an `allow_non_ca` argument.
- MCP tools always name the subcommand (`check`, `diagnose`, `verify-key`)
  and pass the target after `--`, so a target can never be parsed as a
  subcommand or flag.
- The `--no-verify` warning prints once per run instead of once per target
  plus once globally.
- Watch mode: the dead second Ctrl+C registration is gone; the first Ctrl+C
  stops the loop cleanly after the current check (exit 0), a second exits at
  once.

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
