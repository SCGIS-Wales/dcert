# Changelog

All notable changes to dcert are recorded here. Every merge to `main` is a
release; entries collect under `Unreleased` until the next minor release
summary is written.

## Unreleased

### Security

- Supply chain: releases publish `SHA256SUMS` and a CycloneDX SBOM; release
  archives, the SBOM and wheels carry build provenance attestations; the
  container image is scanned with Trivy on every build and each pushed
  digest is signed keylessly with cosign. `SECURITY.md` documents every
  `DCERT_MCP_*` variable and the HTTP mode threat model.
- HTTP mode authorisation and OIDC hardening: per tool scope checks fail
  closed when the tool cannot be determined (batches, non object bodies);
  issuer and JWKS URL must be https; the discovery `issuer` must match and a
  discovered `jwks_uri` must share the issuer's origin; stale JWKS keys are
  capped at `DCERT_MCP_JWKS_MAX_STALE` (24 hours); the header `typ` and the
  `scp`/`scope`/`roles` claims distinguish access tokens from ID tokens;
  scopes are read from `scp` and `scope`; the JWK type and curve must match
  the token algorithm. One audit record per tool call with a redacted
  target. `diagnose_endpoint.no_verify` needs `DCERT_MCP_ALLOW_NO_VERIFY=1`,
  and bearer auth on a non loopback bind warns unless
  `DCERT_MCP_BEHIND_TLS=1`.
- `https://` proxy URLs (from `--proxy`, `DCERT_PROXY` or `HTTPS_PROXY`) are
  refused with a clear error instead of being spoken to in plaintext, which
  exposed the CONNECT request and proxy credentials. TLS to the proxy is a
  recorded follow up.
- Vault and OIDC HTTP clients follow redirects only within the original
  origin, so a redirect can never carry a Vault token or move JWKS
  retrieval to another server.
- Secrets off argv and out of `--help`: the MCP server passes headers and
  request bodies to the CLI through private 0600 files (new
  `--headers-file`, existing `--data-file`), which also lifts the 128 KiB
  single argument limit on bodies; `DCERT_MCP_*` settings are stripped from
  the child environment; `--help` hides the values of secret and proxy
  environment variables; proxy credentials are masked in every error; and
  `x-vault-token`, `x-auth-token`, `api-key`, `ocp-apim-subscription-key`
  and `x-amz-security-token` join the masked headers.
- `dcert-python --transport http|sse` refuses to start without
  authentication: a static bearer token of at least 32 characters
  (`--auth-token`, `DCERT_MCP_AUTH_TOKEN`) or an https OIDC issuer, audience
  and JWKS URL. Requests with a `Host` header other than loopback, the bind
  address or `--allowed-hosts` are answered 400 (S4).
- The Python proxy now forwards the `DCERT_MCP_*` policy variables, the
  Vault settings (`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`,
  `VAULT_CAPATH`, `VAULT_SKIP_VERIFY`), `DCERT_KB_FILE`, `DCERT_PROXY`,
  `DCERT_NOPROXY`, `ALL_PROXY`, `TMPDIR` and `XDG_CACHE_HOME` to
  `dcert-mcp`; previously a hardened deployment lost its policy silently.
- MCP destination policy (S3): `DCERT_MCP_DENY_PRIVATE_TARGETS` (default on
  in HTTP mode) refuses loopback, private, link local and metadata
  addresses, and `DCERT_MCP_ALLOWED_TARGETS` restricts tool calls to listed
  hosts, suffixes, IPs and CIDRs. It covers `target`, `connect_to`,
  `resolve`, `proxy` and AIA issuer URLs, and the CLI child enforces it on
  the address it actually dials (`DCERT_ALLOWED_TARGETS`,
  `DCERT_DENY_PRIVATE_TARGETS`). The OCSP address guard moved to
  `src/netpolicy.rs` and now honours the same policy.
- MCP Vault tools no longer send the server's own token (`VAULT_TOKEN` or
  `~/.vault-token`) to a caller chosen `vault_addr`. The inherited token is
  used only for the server's `VAULT_ADDR` or an address in
  `DCERT_MCP_VAULT_ADDR_ALLOWLIST`; other addresses need an explicit
  `vault_token` (S2).
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

- Numeric options have ranges defined once in `src/limits.rs` and enforced
  by both the CLI and the MCP server: `--timeout` and `--read-timeout`
  1 to 300 seconds, `--issuer-timeout` 1 to 60, `--watch` 1 to 86400,
  `--body-limit` up to 1 MiB. `DCERT_MCP_TIMEOUT=0` and an unknown
  `--mode` are refused at startup, waiting for a subprocess slot is bounded
  by the subprocess timeout ("server busy"), and HTTP shutdown gives
  in-flight requests at most 10 seconds to drain.
- OCSP requests honour the run's proxy settings (an `http://` proxy that
  does not bypass the responder carries the request in absolute URI form)
  and use `--timeout` instead of a fixed five seconds; failing to set a
  socket timeout is an error rather than a warning. AIA fetched issuer
  certificates join the chain only when their key verifies the signature of
  the certificate below them.
- DNS: resolution is bounded by the connect timeout, and every resolved
  address is tried in the resolver's order with the timeout shared between
  them (at least one second each); a failure lists every address attempted.
  The probe, the proxy dial and the OCSP client share this, so a dual stack
  host with one unreachable address no longer fails.
- Deadlines everywhere: every probe now has one wall clock budget of
  `--timeout` plus `--read-timeout` covering the proxy CONNECT, STARTTLS,
  the TLS handshake and the HTTP exchange, enforced by a watchdog that shuts
  the socket down; a server that drips one byte at a time can no longer hold
  a probe open. Sockets get write timeouts as well as read timeouts.
  STARTTLS replies are capped at 64 lines and 64 KiB, and a silent STARTTLS
  server is reported as a timeout instead of an "unexpected banner".
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

- The Chocolatey install test picks the newest release that already carries
  the Windows zip, instead of the newest tag, so it no longer fails while a
  release is still uploading its assets.
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
