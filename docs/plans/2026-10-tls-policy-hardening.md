# dcert hardening and TLS policy conformance plan

Plan for Claude Code. Repository: `SCGIS-Wales/dcert`, branch `main`, version at time of writing `3.0.51`.
Author: Dejan Gregor. Written 2026-10-26 from a full audit of the `main` branch export.

Place this file at `docs/plans/2026-10-tls-policy-hardening.md` in the repository and keep it updated. It is the single source of truth for the work and for resuming it.

---

## 0. Operating instructions for Claude Code

Read this section at the start of every session before touching code.

### 0.1 Resume protocol (auto continue)

Work is tracked by the checkboxes in sections 3 to 10. Every session follows the same loop, so a session that stops for any reason (credits, context, CI wait, network) is resumed by the next one without a handover.

1. `git fetch origin && git checkout main && git pull --ff-only`.
2. Read this file. Find the first PR whose checkbox is not ticked. That is the current PR.
3. `gh pr list --state all --search "<PR id>"` to see whether a branch or PR already exists for it. Use the branch naming in 0.3 to find it. If a branch exists, check it out and read `git log main..HEAD` and `git status` before continuing.
4. If the PR is open and CI is green and all its acceptance criteria are met, merge it (0.4), tick its box in this file on `main` in the same merge (the plan file is part of every PR), and go to step 2.
5. If the PR is open and CI is red, fix it. Never merge red.
6. If no branch exists, create it, implement the PR scope, run the local gate (0.5), push, open the PR with the template in 0.6, then wait for CI with `gh pr checks <N> --watch --fail-fast`.
7. Stop conditions, in which case write the state into the "Session notes" line of the current PR in this file, commit that, push, and end the session: a decision that is listed as "ask Dejan" in the PR scope; a CI failure outside this change set; a credential or network dependency that is not available.
8. Never work on two PRs at once. Never skip a phase gate (0.7).

Session bootstrap prompt (paste into Claude Code to start or resume):

```text
Read docs/plans/2026-10-tls-policy-hardening.md and CLAUDE.md. Follow section 0 exactly. Resume from the first unticked PR, finish it, merge it when green, tick it in the plan, and continue to the next PR. Do not stop between PRs unless a stop condition in 0.1 applies.
```

### 0.2 Repository rules that override anything else

- `CLAUDE.md` in the repository root applies in full. Every commit is authored and committed by `api-py <dejan.gregor@gmail.com>` (local) or `api-py <5954680+api-py@users.noreply.github.com>` (CI). No `Co-Authored-By`, no "Generated with" footers, no AI identity anywhere in commits, PR titles, PR bodies or release notes. Check `git config user.name` and `user.email` before the first commit of every session.
- Every push to `main` triggers the release pipeline (auto tag, version bump with `[skip ci]`, PyPI, Docker, Homebrew, Chocolatey). Therefore every merged PR is a release. Keep PRs small and shippable; a half built feature never lands on `main`. Use feature flags or unexported modules if a PR must land before its feature is usable.
- Languages stay as they are: Rust 2024 edition for the CLI and MCP server, Python 3.12+ with FastMCP for the `python/` package, `click` for any new Python CLI code, configuration in YAML not in code.
- Oxford English in all documentation, comments, help text and knowledge base prose. Do not use hyphens or dashes as punctuation in prose (identifiers such as `--cipher-list` and `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` are not prose).

### 0.3 Branch and commit conventions

- Branch name: `plan/<phase>-<pr>-<slug>`, for example `plan/1-2-vault-token-fallback`.
- One PR per checkbox. Conventional commit subjects (`fix:`, `feat:`, `refactor:`, `test:`, `docs:`, `ci:`), under 72 characters, body explains why.
- Each PR updates `CHANGELOG.md` (create it in PR 0.1 if absent) under an `Unreleased` heading and ticks its own checkbox in this plan.

### 0.4 Merge command

```bash
# Verify authorship on the PR branch (only api-py, no AI trailers), then squash merge
git log main..HEAD --format='%an <%ae>%n%b'
gh pr merge <N> --squash --delete-branch --author-email 5954680+api-py@users.noreply.github.com
# Verify after merge; the only name allowed is api-py (plus GitHub web-flow)
git log origin/main -5 --format='%an|%cn|%(trailers:key=Co-authored-by,valueonly)' | sort -u
```

### 0.5 Local gate (must pass before every push)

```bash
# Rust: format, lint with warnings as errors, tests on system OpenSSL
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
# Rust: the same with vendored OpenSSL 3.6 (post quantum paths); run at least once per PR that touches src/tls.rs, src/keyex.rs, src/ciphers.rs or src/tlspolicy.rs
cargo test --features vendored
# Python package
cd python && ruff check src tests ../scripts && ruff format --check src tests ../scripts && mypy && pytest && cd ..
# Knowledge base (after Phase 5 adds the lint): validates entries, references and SOURCES.md cross links
cargo run -- kb validate kb/diagnostics.yaml && cargo run -- kb validate --reference kb/reference.yaml
```

### 0.6 PR body template

```markdown
## Scope
Plan item: <phase>.<pr> <title> (docs/plans/2026-10-tls-policy-hardening.md)

## What changed
- ...

## Acceptance criteria (copied from the plan, each ticked)
- [x] ...

## Tests
- ...

## Risk and rollback
- ...
```

### 0.7 Phase gates

A phase is complete when every PR in it is merged and its exit criteria (listed at the end of each phase) hold on `main`. Do not start the next phase before that. Phases 1 and 2 are release worthy on their own and must not wait for later phases.

### 0.8 Definition of done for every PR

- Unit tests for every new function and every bug fix (regression test that fails before the fix).
- No new `unwrap`, `expect`, `panic`, `todo` or `dbg!` outside tests (clippy enforces).
- No live network in tests. Loopback servers only; opt in live tests are gated by an environment variable and skipped by default.
- README, `--help` text, MCP tool descriptions and `python/README.md` updated in the same PR as the behaviour.
- `CHANGELOG.md` entry.

---

## 1. Context and verified facts

### 1.1 What dcert is today

- Rust CLI `dcert` (`src/`) and MCP server `dcert-mcp` (`src/mcp/`), 24 MCP tools that run the CLI as a subprocess with `--format json`. Python package `dcert` (`python/`) is a FastMCP proxy that downloads the Rust binary and types 11 of the 24 tools.
- TLS is OpenSSL via the `openssl` crate. One connector builder (`src/tls.rs` `build_connector`) serves HTTPS, STARTTLS and the post quantum probe. The verify callback captures the chain and per depth errors; `src/mtls.rs` installs a certificate callback that records `CertificateRequest`.
- Knowledge bases are data: `kb/diagnostics.yaml` (failure signatures scored by `src/diagnose.rs`) and `kb/reference.yaml` (CloudFront and API Gateway meanings, `src/kbref.rs`), both embedded with `include_str!`.
- CI: hosted Ubuntu runners link OpenSSL 3.0; a separate job tests with `--features vendored` (OpenSSL 3.6). Linux release binaries and the Docker binary are built on ubuntu 22.04 (OpenSSL 3.0) while the Docker image runs on Debian trixie (OpenSSL 3.5).

### 1.2 Facts verified against primary sources on 2026-10-26

- RFC 10024 (August 2026, Standards Track) defines the hybrid groups `X25519MLKEM768` (0x11EC), `SecP256r1MLKEM768` (0x11EB) and `SecP384r1MLKEM1024` (0x11ED). The repository cites it correctly in code and README; no knowledge base file cites it.
- OpenSSL 3.x disallows SSLv3, TLS 1.0 and TLS 1.1 at security level 1 and above (the default is level 1; Debian and Ubuntu ship level 2). Any TLS 1.0 or 1.1 probe needs `@SECLEVEL=0` in the cipher string.
- OpenSSL 3.5 (April 2025, LTS) is the first release with ML-KEM; `SSL_get0_group_name` exists from 3.2.
- AWS Application Load Balancer post quantum policies (source: `docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html`). Thirteen PQ policies exist, six standard and seven FIPS. AWS states that PQ policies "support both classical and post-quantum ML-KEM key exchange algorithms" and names the hybrid groups `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` and `X25519MLKEM768`. Console default for a new HTTPS listener is `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`; CLI, CloudFormation and CDK default is `ELBSecurityPolicy-2016-08`. ALB does not support custom security policies.

| Policy | Protocols | TLS 1.3 suites | TLS 1.2 ciphers |
|---|---|---|---|
| `ELBSecurityPolicy-TLS13-1-3-PQ-2025-09` | TLS 1.3 only | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` | none |
| `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` | TLS 1.3, TLS 1.2 | same three | `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES128-GCM-SHA256`, `ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES256-GCM-SHA384` |

IANA names and code points of those four TLS 1.2 ciphers: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B), `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F), `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (0xC02C), `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (0xC030).

- ALB connection log fields: `tls_protocol` (5), `tls_cipher` (6), `tls_verify_status` (11, `Success` or `Failed:<code>`), `tls_keyexchange` (13). mTLS failure codes: `ClientCertMaxChainDepthExceeded`, `ClientCertMaxSizeExceeded`, `ClientCertCrlHit`, `ClientCertCrlProcessingError`, `ClientCertUntrusted`, `ClientCertNotYetValid`, `ClientCertExpired`, `ClientCertTypeUnsupported`, `ClientCertInvalid`, `ClientCertPurposeInvalid`, `ClientCertRejected`, `ClientCertIncompatible`, `UnmappedConnectionError`.
- ALB mTLS: passthrough mode forwards the chain in `X-Amzn-Mtls-Clientcert`; verify mode sets `X-Amzn-Mtls-Clientcert-Serial-Number`, `-Issuer`, `-Subject`, `-Validity`, `-Leaf`. Session resumption is not supported with mTLS. "Advertise CA subject name" sends the trust store CA DNs in `CertificateRequest`. Trust store CA bundles are PEM batches; keys RSA 2K to 8K or ECDSA P-256/384/521.
- Amazon CloudFront has used TLS 1.3 to origins by default since 2025-11-20. The reference knowledge base still says CloudFront never speaks TLS 1.3 to origins.

### 1.3 Audit summary (what the plan fixes)

Security, High: (S1) `DCERT_MCP_FILE_ROOT` confinement bypass with relative paths because the child process never gets `current_dir` and receives the unresolved path (`src/mcp/validate.rs:149-153`, `src/mcp/exec.rs:81-86`). (S2) The server's inherited `VAULT_TOKEN` or `~/.vault-token` is sent to any `vault_addr` a caller supplies when no allow list and no `VAULT_ADDR` are configured (`src/mcp/params_vault.rs:170-197`, `src/vault.rs:28-61`). (S3) No SSRF policy: tools can dial loopback, RFC 1918, link local and the metadata address, and `diagnose_endpoint` is a general HTTPS request primitive. (S4) The Python HTTP and SSE transports have no authentication and drop the `DCERT_MCP_*` and `VAULT_*` policy variables.

Security, Medium: headers (including bearer tokens) and request bodies travel on argv; clap `env =` without `hide_env_values` prints secrets in `--help`; `https://` proxy URLs are accepted but spoken to in plaintext; proxy credentials leak into error text; per tool authorisation fails open on JSON-RPC batches; OIDC does not require https or same origin for issuer and JWKS and serves stale keys without bound; `no_verify` is exposed through MCP without a gate; a check then use race on the temp directory root; target file paths are not confined.

Reliability, Medium: no write timeout anywhere; no overall handshake deadline; unbounded STARTTLS response loop; DNS resolution uses only the first address and has no timeout; OCSP ignores the proxy; AIA fetched issuers are appended without checking they issued the certificate; request bodies over 128 KiB fail to spawn (argv limit); the Linux and Docker binaries are built against OpenSSL 3.0 so `key_exchange_class` is `unknown` and `--pq-probe` reports `not_supported` even when ML-KEM negotiated; the CI test job runs `--all-features` which silently enables `vendored`, so the shipped OpenSSL 3.0 code path is never unit tested.

Parity: `--min-tls` and `--max-tls` exist only on `tls_connection_info`; `--kb-file`, `--watch`, `--diff`, `--format`, `--expired-only`, `--body-limit`, `--no-diagnose`, `--sort-expiry`, `--data-file` and `--debug` have no MCP parameter; `kb list|show|validate|schema|topics` have no tool; `create_truststore.allow_non_ca` defaults to true in MCP and false in the CLI; `--ciphers` is forwarded by MCP but only affects pretty output; `export_pem` without `output_path` returns no PEM because `pem_data` is `#[serde(skip)]`; `explain_edge_term` treats exit 1 as no match but the CLI returns 2; `--starttls` with a bare host dials `https://host`; the Python typed layer covers 11 of 24 tools and its `ConnectionOptions` omits 14 keys; `passthrough_env` drops `VAULT_*`, `DCERT_MCP_*`, `DCERT_KB_FILE`, `DCERT_PROXY`, `DCERT_NOPROXY` and `ALL_PROXY`.

Knowledge base: no ALB or NLB coverage at all (no platform, no category, no reference service, no `ELBSecurityPolicy-*`); remediation text names flags that do not exist (`--tls-version`, `--ciphers` as a selector, `--http1.1`); `tls.handshake.protocol-version` overclaims that current CDNs refuse TLS 1.0 and 1.1; `apigateway.tls.security-policy` claims CBC only offers are refused; `certificate_unknown` (alert 46) is conflated with `unknown_ca`; entries that need chain evidence can never fire in default mode because a verification failure takes the error path, which carries no chain; the engine never sees the negotiated cipher, group, PQ probe verdict, the four state `client_auth` or `acceptable_client_cas`; no entry covers `insufficient_security`, `no_application_protocol`, `illegal_parameter`, `decode_error`, `unexpected eof`, group mismatch, STARTTLS, renegotiation, 0 RTT or OCSP stapling; `SOURCES.md` is not tested and is out of sync with the URLs the entries cite; the schema does not reject unknown signal fields.

Duplication: probe option structs built in two places (`src/output.rs:826-845`, `src/mcp/tools/cert.rs:563-592`, the second ignoring `DCERT_PROXY`, CA and SNI); three subprocess runners that inject flags differently; `tool_reply` and `vault_reply` duplicates plus nine hand expanded copies of the same match; proxy environment parsed three times with different precedence (`src/proxy.rs:52-71` versus `src/mcp/config.rs:149-171`); defaults copied between clap, MCP params, `src/tls.rs`, `src/mcp/config.rs` and `python/src/dcert/config.yaml`; enum validation copied by hand instead of using the clap `ValueEnum` types; `print_structured` bypassed in four places; the `--no-verify` warning printed twice.

---

## 2. Target design

Keep the architecture; add four things and remove the duplication around them.

1. `src/tlsopts.rs`: one `TlsOptions` struct (`#[derive(clap::Args, serde::Deserialize, schemars::JsonSchema)]`) that owns every TLS knob: `min_tls`, `max_tls`, `cipher` (any notation, repeatable), `cipher_list`, `cipher_suites`, `groups`, `tls_profile`, `pq_probe`, `sni`, `starttls`, `allow_legacy_tls`, `cipher_notation`. It has exactly one `to_cli_args(&self) -> Vec<OsString>` and one `to_connector_settings(&self)`. The CLI flattens it into `CheckArgs`; every MCP probe tool flattens it into its params; the MCP layer serialises it with `to_cli_args`. Parity becomes a property of the type, and a test asserts that every field maps to a clap long flag that `Cli::command()` knows.
2. `src/ciphers.rs`: a cipher suite model. One static table generated from the IANA TLS Cipher Suites registry (code point, IANA name, OpenSSL name, protocol, key exchange, authentication, encryption, MAC, AEAD, forward secrecy, status) plus a runtime overlay from the linked OpenSSL (`SSL_get1_supported_ciphers` via the `openssl` crate) so dcert can say "this build cannot offer X". Parsing accepts IANA, OpenSSL, `0xC02F`, `C02F`, `0xC0,0x2F` and comma or colon separated lists, case insensitive. Output always carries all three notations.
3. `src/tlspolicy.rs` and `kb/tls_policies.yaml`: a catalogue of named TLS security policies (AWS ALB and NLB `ELBSecurityPolicy-*`, CloudFront viewer policies, API Gateway policies, Mozilla modern and intermediate) with protocols, suites, ciphers, groups, source URL and retrieval date, validated by a JSON schema and a test. A conformance engine runs a bounded set of handshakes against a target and reports expected versus observed per protocol version, cipher, suite and group, with a verdict of `conformant`, `non_conformant` or `inconclusive`.
4. Diagnostics evidence extended with negotiated cipher, group, PQ verdict, `client_auth` state, acceptable CAs, a parsed TLS alert, transport (direct, proxy, STARTTLS) and policy conformance; new platforms `aws_alb` and `aws_nlb`; new signal kinds for each.

Exit codes: keep 0 to 8; add `9` for policy non conformance and `10` for policy test inconclusive.

---

## 3. Phase 0: harness, CI truth and quick fixes

Goal: every later PR can be tested hermetically, and CI tests what ships.

- [x] **PR 0.1 Hermetic TLS test harness.** Move the loopback helpers out of `tests/cli_tests.rs` into `tests/support/mod.rs` (shared by all integration tests) and add `src/testutil.rs` under `#[cfg(test)]` for unit tests. Builder API: `TlsServer::builder().versions(min, max).cipher_list(..).ciphersuites(..).groups(..).security_level(u32).client_auth(ClientAuthMode).alpn(..).identity(rsa|ecdsa|both).respond(..)`. Generate RSA and ECDSA P-256 test identities and a test CA at build time of the test (OpenSSL, in memory) instead of committing more fixtures. Add `env_remove` of `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` (both cases), `DCERT_PROXY`, `DCERT_NOPROXY` in `dcert_bin()`. Add `CHANGELOG.md`. Acceptance: existing tests pass unchanged; a new test proves the builder can pin TLS 1.2 only with a single cipher and that the client negotiates exactly it.
- [x] **PR 0.2 CI tests what ships.** Change the main test job to `cargo test` and `cargo clippy --all-targets -- -D warnings` without `--all-features`; keep the vendored job. Add a job that runs the ubuntu 22.04 built Linux binary inside `debian:trixie` (OpenSSL 3.5) against a loopback server with `--pq-probe` and asserts the negotiated group is named (this fails until PR 2.6 and is allowed to fail until then with `continue-on-error: true` and a tracking comment; flip to required in PR 2.6). Pin every GitHub Action to a commit SHA, including `pypa/gh-action-pypi-publish`. Add `pip-audit` for `python/`. Add an MSRV job on `1.91`. Acceptance: all jobs green on `main`.
- [x] **PR 0.3 Quick correctness fixes found by the audit.** (a) `--starttls` with a bare host: strip the scheme before splitting host and port (`src/output.rs:480-491`), keep the client identity on the STARTTLS path (`src/tls.rs:1466`), add tests with a loopback SMTP STARTTLS stub from PR 0.1. (b) `export_pem` without `output_path` returns the PEM in the tool text; make the CLI emit `pem_data` in JSON when `--export-pem -` is given, and use that from MCP. (c) `explain_edge_term` maps exit code 2 to "no match". (d) `create_truststore.allow_non_ca` defaults to false in MCP. (e) MCP always emits the `check` subcommand and places the target after `--` so a target can never be routed as a subcommand. (f) The `--no-verify` warning prints once. (g) The dead `ctrlc` second registration in watch mode is removed and watch mode exits cleanly on Ctrl+C via the existing handler and an atomic flag. Acceptance: regression test for each item.

Exit criteria: harness in use by at least three tests; CI runs system OpenSSL tests; all seven quick fixes merged.

---

## 4. Phase 1: security

Goal: close every High and Medium security finding. Each PR is independently releasable.

- [x] **PR 1.1 File root confinement (S1).** `validate_path` returns the canonical absolute path and the tool passes that path to the child; `spawn_dcert` sets `current_dir` to the first configured root. Remove `std::env::temp_dir()` from the default roots (default becomes the working directory only; document `DCERT_MCP_FILE_ROOT`). Confine `target` when it is a file path (apply `validate_path` whenever the target is not a URL or hostname). Tests: relative path outside root is rejected when cwd differs from root; symlink escape rejected; file existence oracle closed.
- [x] **PR 1.2 Vault token fallback (S2).** The MCP server never lets the child inherit `VAULT_TOKEN` or read `~/.vault-token` unless `vault_addr` equals the operator configured `VAULT_ADDR` or is in `DCERT_MCP_VAULT_ADDR_ALLOWLIST`. With neither configured, token auth requires an explicit `vault_token` parameter and `vault_addr` is refused with a message naming the two variables. Tests for each branch.
- [x] **PR 1.3 Destination policy (S3).** New `DCERT_MCP_ALLOWED_TARGETS` (comma separated hostnames, suffix patterns like `.corp.example`, IPs and CIDRs) and `DCERT_MCP_DENY_PRIVATE_TARGETS` (default `1` in HTTP mode, `0` in stdio). Applies to `target`, `connect_to`, `resolve`, `proxy` and the AIA URLs followed by `resolve_issuers`. Denied by default in HTTP mode: loopback, RFC 1918, link local (`169.254.0.0/16`, `fe80::/10`), `fc00::/7`, and the metadata addresses `169.254.169.254` and `fd00:ec2::254`. Reuse the existing OCSP guard (`src/ocsp.rs:25-77`) by moving it into `src/netpolicy.rs`. Tests cover every range and the allow list override.
- [x] **PR 1.4 Python transport and environment (S4).** `dcert-python --transport http|sse` refuses to start without `--auth-token` or an OIDC configuration and validates the `Host` header against loopback plus `--allowed-hosts`. `passthrough_env` in `config.yaml` adds `DCERT_MCP_*`, `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, `VAULT_CAPATH`, `VAULT_SKIP_VERIFY`, `DCERT_KB_FILE`, `DCERT_PROXY`, `DCERT_NOPROXY`, `ALL_PROXY`, `all_proxy`, `TMPDIR`, `XDG_CACHE_HOME`. Tests in `python/tests`.
- [x] **PR 1.5 Secrets off argv and out of help.** Headers and `data` go to the child through a 0600 temporary file (`--headers-file`, new) and `--data-file` respectively; add `hide_env_values = true` to every clap `env =` secret and proxy argument; strip `DCERT_MCP_*` secrets from the child environment; extend `SENSITIVE_HEADERS` with `x-vault-token`, `x-auth-token`, `api-key`, `ocp-apim-subscription-key`, `x-amz-security-token`; mask credentials in every error that embeds a proxy URL (`src/proxy.rs`, `src/http.rs`). This also fixes the 128 KiB argv limit. Tests: `--help` with `DCERT_CERT_PASSWORD` set shows no value; `/proc/self/cmdline` of the spawned child contains no header values (Linux only test).
- [x] **PR 1.6 Proxy and redirect hygiene.** Reject `https://` proxy URLs until TLS to the proxy is implemented (clear error), or implement TLS to the proxy using `build_connector`; choose the second if it fits in the PR, otherwise the first. Same origin redirect policy for the Vault and OIDC reqwest clients. Tests with a loopback proxy stub. Session notes: shipped the rejection (TLS to the proxy needs a generic stream type through `dial`, over the PR budget). Follow up: implement TLS to `https://` proxies with `build_connector` and a `Box<dyn Read + Write>` dial stream.
- [x] **PR 1.7 HTTP mode authorisation and OIDC hardening.** Per tool scope check fails closed when the tool name cannot be determined (batches, non object bodies). OIDC: require `https` for issuer and JWKS URL, compare discovery `issuer`, require JWKS same origin as the issuer unless `DCERT_MCP_OIDC_JWKS_URL` is explicit, cap JWKS staleness at 24 hours (`DCERT_MCP_JWKS_MAX_STALE`), check `typ` is `at+jwt` when present and require `scp`, `scope` or `roles` otherwise, read scopes from both `scp` and `scope`, bind JWK `kty`/`crv` to the header `alg`. Log one audit event per tool call with the tool name and a redacted target. Gate `diagnose_endpoint.no_verify` behind `DCERT_MCP_ALLOW_NO_VERIFY=1`. Warn at startup when bearer auth is configured on a non loopback bind without `DCERT_MCP_BEHIND_TLS=1`. Tests with wiremock for every OIDC branch.
- [x] **PR 1.8 Supply chain.** Add `actions/attest-build-provenance` for release archives and wheels, cosign keyless signing for the GHCR image, `SHA256SUMS` and the CycloneDX SBOM as release assets, Trivy scan of the image. Update `SECURITY.md` with the new environment variables and the threat model for HTTP mode.

Exit criteria: no High or Medium security finding from section 1.3 remains; `SECURITY.md` documents every `DCERT_MCP_*` variable; CI signs and attests.

---

## 5. Phase 2: reliability

- [x] **PR 2.1 Deadlines everywhere.** Add `set_write_timeout` wherever `set_read_timeout` exists; introduce a `Deadline` helper (wall clock) used by the handshake loop, the STARTTLS exchange, the proxy CONNECT and the HTTP read, so that total time per probe never exceeds `--timeout + --read-timeout` by more than one read interval. STARTTLS `read_response` caps lines (64) and bytes (64 KiB). Timeouts are reported as timeouts, not as parse errors. Tests with a drip server from the harness (sends one byte per 200 ms).
- [x] **PR 2.2 DNS.** Resolve with a timeout (spawn the blocking `getaddrinfo` on a thread with a channel and the connect timeout) and try every returned address in order (IPv6 then IPv4 or Happy Eyeballs lite: sequential with the per address connect timeout divided by the address count, minimum 1 s). Report every attempted address on failure, as `connect_via_override` already does. Shared by probe, proxy and OCSP.
- [x] **PR 2.3 OCSP and AIA through the proxy and verified.** OCSP uses `ProxyConfig` and `--timeout`; AIA fetched certificates are only appended when they verify the signature of the certificate below them; `set_read_timeout` failure is an error. Tests with loopback OCSP and AIA stubs (wiremock) and a fake proxy.
- [x] **PR 2.4 Input ranges.** `value_parser` ranges for `--timeout`, `--read-timeout`, `--issuer-timeout`, `--watch`, `--body-limit` in clap and the same ranges in MCP params (single source: constants in `src/limits.rs`). `DCERT_MCP_TIMEOUT=0` is rejected at startup. Semaphore acquisition is bounded by the subprocess timeout. Unknown `--mode` is an error. Graceful shutdown has a 10 s drain deadline.
- [x] **PR 2.5 Python binary freshness.** The downloader records the version and digest of the installed binary in a sidecar JSON and re downloads when the package version changes or the digest no longer matches the embedded checksums; the install directory is created `0700`.
- [x] **PR 2.6 Post quantum on the shipped binaries.** Build the Linux release and the Docker binary against OpenSSL 3.5 or later: either build in a `debian:trixie` container (glibc 2.41, document the new minimum) or, to keep the ubuntu 22.04 glibc floor, resolve `SSL_get0_group_name` at runtime with `dlsym` when the compile time cfg is off. Prefer the `dlsym` route because it keeps the published glibc requirement. Flip the PR 0.2 trixie job to required. `dcert --version` prints both the compile time and the runtime OpenSSL versions when they differ.
- [x] **PR 2.7 IMAP STARTTLS and Windows signals.** IMAP response reader tolerates untagged lines before the tagged `OK`; `dcert-mcp` handles `Ctrl+Break` and console close on Windows with `tokio::signal::windows`.

Exit criteria: a drip server test for every network path passes; `--pq-probe` names the group from the Docker image; all timeouts have tests.

---

## 6. Phase 3: shared TLS options and subprocess plumbing (deduplication core)

Goal: one definition of every option, one serialiser, one subprocess runner, so the later feature phases add each option once.

- [x] **PR 3.1 `TlsOptions` and `ProbeOptions`.** Create `src/tlsopts.rs` as described in section 2. Move `min_tls`, `max_tls`, `cipher_list`, `cipher_suites`, `groups`, `tls_profile`, `pq_probe`, `sni`, `starttls`, `ciphers` (renamed field `cipher_notation`, flag kept as `--ciphers` with `--cipher-notation` as the new canonical name and `--ciphers` as a hidden alias) into it; flatten into `CheckArgs`. Replace the two `TlsProbeOptions` builders with one `ProbeOptions::from(&TlsOptions, &ConnectionOptions, &ClientIdentity)`. `verify-key` over HTTPS uses the same builder, so it gains proxy, CA and SNI handling for free. Tests: existing behaviour unchanged (byte identical pretty and JSON output on fixtures).
- [x] **PR 3.2 One MCP argument serialiser.** `TlsOptions`, `MtlsParams`, `ConnectionOptions` and `HttpOptions` implement a `ToCliArgs` trait with a small `ArgBuilder` (`flag`, `value`, `repeat`, `env`) that always emits `--flag=value` form so values starting with `-` are safe. Delete the thirteen hand written `if let Some` blocks. Add the parity test: every `JsonSchema` property of every probe tool maps to a long flag that `Cli::command()` accepts for `check`, and every `check` flag is either in a tool schema or in an explicit `CLI_ONLY` allow list with a reason (`--watch`, `--diff`, `--format`, `--debug`).
- [ ] **PR 3.3 One subprocess runner and one reply path.** Collapse `run_dcert_with_env`, `run_dcert_raw` and `run_dcert_vault` into `run_dcert(Invocation)` where `Invocation { subcommand, args, env, stdin, timeout }`; the runner injects `--timeout`, `--read-timeout` and `--debug` consistently. Collapse `tool_reply` and `vault_reply` and the nine inline matches into one `reply(invocation, banner, codes)`. Delete the `args_refs` conversions. Vault tools stop forcing `--debug`.
- [ ] **PR 3.4 Single sources for defaults, proxy environment and enums.** `src/limits.rs` holds every default and range (timeouts, body limit, expiry warn, TTL, mounts, KV version, key names) used by clap, MCP params and `src/tls.rs`; `python/src/dcert/config.yaml` defaults are generated from it by `scripts/sync_defaults.py` (run in CI, fails if stale). `ProxyConfig::from_env` is the only proxy environment reader and honours `DCERT_PROXY`/`DCERT_NOPROXY`; `src/mcp/config.rs` and `src/diagnose.rs` call it. MCP enum validation uses the clap `ValueEnum` types (`TlsProfile`, `KeyAlgorithmArg`, `VaultAuthMethod`, `StarttlsProtocol`, `HttpMethod`, `HttpProtocol`, `CipherNotation`) through one `parse_enum::<T>()`.
- [ ] **PR 3.5 Output path.** Route the four bypasses (multi target JSON/YAML, verify key per pair, `kb show`, `kb schema`) through `print_structured`; one `render_diagnosis` used by `output.rs` and `main.rs`; remove the duplicated watch loop by extracting `run_once()`.

Exit criteria: parity test green; `grep -c 'args.push("--' src/mcp` is zero; one proxy environment reader; one default per setting.

---

## 7. Phase 4: cipher suite model, notations and TLS version coverage

- [ ] **PR 4.1 `src/ciphers.rs` table and parser.** Add `scripts/gen_cipher_table.py` (click CLI, reads the IANA CSV `tls-parameters-4.csv`, writes `src/ciphers_table.rs`; the generated file is committed and a CI check regenerates and diffs). Each row: code point, IANA name, OpenSSL name (from the OpenSSL `ssl/s3_lib.c` mapping, embedded in the script as a YAML file `scripts/cipher_openssl_names.yaml`), protocol (`tls12` or `tls13`), key exchange, authentication, encryption, MAC, flags (AEAD, PFS, export, NULL, anonymous, FIPS approved). `Cipher::parse(&str)` accepts every notation in section 2 and returns `Result<&'static Cipher, CipherParseError>` with "did you mean" suggestions (Levenshtein under 3). `CipherSet::parse_list` accepts colon or comma separated lists and OpenSSL keywords (`ECDHE+AESGCM`, `HIGH`, `!aNULL`) by expanding them through the linked OpenSSL. Runtime overlay: `Cipher::offerable()` consults `SSL_get1_supported_ciphers` once (`OnceLock`). Unit tests: every table row round trips IANA to OpenSSL to code point; parsing of each notation; the four ALB TLS 1.2 ciphers and three TLS 1.3 suites parse from all notations.
- [ ] **PR 4.2 `--cipher` and cipher notation in every output.** New repeatable `--cipher <ANY NOTATION>` on `TlsOptions`; dcert sorts the parsed set into a TLS 1.2 cipher list and a TLS 1.3 suite list and applies both (so `--cipher 0xC02F --cipher TLS_AES_128_GCM_SHA256` works). `--cipher-list` and `--cipher-suites` remain as raw OpenSSL passthrough. JSON and YAML output of `tls_cipher` becomes an object `{openssl, iana, code_point, protocol, forward_secrecy, aead}` behind the new `cipher_notation` setting being `all` by default; `--cipher-notation iana|openssl|all` applies to pretty, JSON and YAML (fixes the MCP no effect defect). Add `dcert ciphers list [--protocol 1.2|1.3] [--offerable]` and `dcert ciphers explain <any notation>` subcommands and the MCP tools `list_cipher_suites` and `explain_cipher_suite` (no network). Tests: loopback server pinned to one cipher negotiated through each notation.
- [ ] **PR 4.3 TLS 1.0 and 1.1 probing, opt in.** Extend `TlsVersionArg` with `1.0` and `1.1`. Offering them requires `--allow-legacy-tls`, which sets `@SECLEVEL=0` on the cipher string for that handshake only and prints a one line warning; without the flag `--min-tls 1.0` is a clear error. `tls_version` in output stays a string. Tests: harness server pinned to TLS 1.1 is rejected by default and accepted with the flag.
- [ ] **PR 4.4 Cipher and version enumeration.** `dcert tls-scan <target>` (and MCP `tls_scan`): for each protocol version 1.0 to 1.3 (legacy versions only with `--allow-legacy-tls`) report accepted or rejected with the alert, then enumerate accepted ciphers per version by iterating the offerable set one cipher per handshake (bounded concurrency 4, `--max-handshakes` default 120), and groups by iterating the known group list. Output: table in pretty, structured in JSON. Each handshake records the negotiated cipher in all notations, the group, the leaf key type and the alert on rejection. Tests against the harness with two certificates (RSA and ECDSA) to prove key type aware enumeration.

Exit criteria: `dcert ciphers explain C02F`, `dcert ciphers explain TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and `dcert ciphers explain ECDHE-RSA-AES128-GCM-SHA256` print the same record; `tls-scan` against the harness lists exactly the configured ciphers.

---

## 8. Phase 5: TLS security policy catalogue and conformance testing

Goal: "does this endpoint behave exactly like security policy X?" for every AWS policy, with the two requested policies tested first.

- [ ] **PR 5.1 Catalogue `kb/tls_policies.yaml` and schema.** Structure per policy: `id`, `provider` (`aws_alb`, `aws_nlb`, `aws_cloudfront`, `aws_api_gateway`, `mozilla`), `protocols` (list of `1.0` to `1.3`), `tls13_suites` (IANA), `tls12_ciphers` (IANA; the loader accepts any notation and normalises), `groups` (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, `X25519`, `prime256v1`, `secp384r1`, as applicable), `fips`, `post_quantum`, `default_for` (`console`, `cli`, `backend`), `source_url`, `retrieved` (date), `notes`. Seed with all 13 ALB PQ policies and every other current `ELBSecurityPolicy-*` listed on the ALB and NLB pages, the CloudFront viewer policies (`TLSv1.2_2021`, `TLSv1.2_2025`, `TLSv1.3_2025` and the legacy ones), the API Gateway `TLS_1_0`, `TLS_1_2` and enhanced `SecurityPolicy_*` policies, and Mozilla modern and intermediate. Use the exact cipher lists from the AWS pages; where AWS lists only PQ groups, record the classical groups as `unspecified_classical: true` rather than inventing a list. Add `scripts/fetch_aws_tls_policies.py` (click, `aws elbv2 describe-ssl-policies` via boto3 when credentials exist, otherwise parses the saved documentation HTML) that writes the YAML and a `kb/tls_policies.schema.json` generated by schemars; a test validates the catalogue and asserts the two required policies have the exact suites and ciphers from section 1.2. Add `dcert policy list [--provider]` and `dcert policy show <id>` and MCP `list_tls_policies`, `show_tls_policy`.
- [ ] **PR 5.2 Conformance engine `src/tlspolicy.rs`.** `PolicyTest::run(target, policy, options) -> PolicyReport`. Steps, each a named check with `expected`, `observed`, `evidence` and `outcome` (`pass`, `fail`, `not_testable`, `not_applicable`):
  1. Discovery handshake (defaults): records leaf key types presented; a second and third handshake offering only RSA ciphers and only ECDSA ciphers detect dual certificate listeners. Ciphers whose authentication key type the listener does not hold are `not_applicable`, not `fail`.
  2. Protocol versions: for each of 1.0, 1.1, 1.2, 1.3 a handshake with `min = max = v` (legacy versions only when `--allow-legacy-tls`, else `not_testable`); expected accept iff `v` is in the policy.
  3. TLS 1.2 ciphers in the policy: one handshake each with `max = 1.2` and that cipher alone; expected accept and negotiated cipher equal to it.
  4. TLS 1.2 ciphers not in the policy: the union of all catalogued TLS 1.2 ciphers minus the policy set, filtered to those the linked OpenSSL can offer; expected reject (`handshake_failure` or `insufficient_security`).
  5. TLS 1.3 suites in the policy: one handshake each with `min = 1.3` and that suite alone; expected accept and negotiated equal. Suites not in the policy (`TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`, and `TLS_CHACHA20_POLY1305_SHA256` for FIPS policies): expected reject.
  6. Groups: each policy group alone with `min = 1.3`; expected accept and negotiated equal; ML-KEM groups are `not_testable` when the linked OpenSSL predates 3.5. For PQ policies also `X25519` alone must be accepted (classical fallback). For non PQ policies the three hybrids alone must be rejected.
  7. Verdict: `conformant` when every applicable check passed; `non_conformant` when any check failed, listing deviations first; `inconclusive` when no check failed but at least one was `not_testable`. `--strict` turns `inconclusive` into exit 10. Exit codes 0, 9, 10.
  `--identify` mode runs steps 2 to 6 once and ranks catalogued policies by match, naming the best fit and the deviations. Bounded concurrency 4, every handshake uses the shared `ProbeOptions` (proxy, overrides, SNI, mTLS identity, timeouts). Pretty output is a table; JSON is the full report. CLI: `dcert policy test <target> --policy <id> [--versions 1.2,1.3] [--identify] [--strict]`. MCP: `tls_policy_test` with the same parameters.
- [ ] **PR 5.3 Required policy tests (hermetic) for `ELBSecurityPolicy-TLS13-1-3-PQ-2025-09` and `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`.** Add `tests/policy_alb_pq.rs` using the PR 0.1 harness with an `emulate_policy(id)` helper that configures `SslAcceptor` from the catalogue (min and max version, `set_cipher_list` for TLS 1.2, `set_ciphersuites` for TLS 1.3, `set_groups_list` to the policy groups plus `X25519:prime256v1:secp384r1`, security level 2, RSA identity; a second variant with RSA and ECDSA). Tests, each run for the pretty and JSON output and asserting the exit code:
  - `tls13_1_3_pq_tls13_conformant`: emulated server, `--policy ELBSecurityPolicy-TLS13-1-3-PQ-2025-09 --versions 1.3` is `conformant`; every suite check passes; group checks pass under `--features vendored` and are `not_testable` under OpenSSL 3.0 (both cases asserted with `cfg`).
  - `tls13_1_3_pq_tls12_rejected`: the emulated server refuses a TLS 1.2 client (`--max-tls 1.2` fails with a `protocol_version` alert) and the policy test records "TLS 1.2 expected reject, observed reject" with `pass`.
  - `tls13_1_3_pq_detects_tls12_enabled`: server misconfigured to also allow TLS 1.2 is `non_conformant` with the single deviation "TLS 1.2 accepted", exit 9.
  - `tls13_1_2_res_pq_tls13_conformant` and `tls13_1_2_res_pq_tls12_conformant`: run with `--versions 1.3` and `--versions 1.2`; all four TLS 1.2 ciphers negotiate (the ECDSA pair against the dual certificate server, `not_applicable` against the RSA only server) and the negative set is rejected.
  - `tls13_1_2_res_pq_detects_cbc_cipher`: server additionally allows `ECDHE-RSA-AES128-SHA256`; `non_conformant` with that cipher named in all three notations.
  - `tls13_1_2_res_pq_detects_tls11`: server allows TLS 1.1; `non_conformant` only when run with `--allow-legacy-tls`, `inconclusive` otherwise (documents why the flag matters).
  - `tls13_1_2_res_pq_identify`: `--identify` against the emulated server names `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` as best fit and `ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09` as the next candidate differing only by ChaCha20.
  - Catalogue unit tests in `src/tlspolicy.rs`: both policies load; `TLS13-1-3-PQ` has no TLS 1.2 ciphers and protocols `[1.3]`; `TLS13-1-2-Res-PQ` has exactly the four ciphers and protocols `[1.2, 1.3]`; both list the three RFC 10024 groups; the FIPS twins lack ChaCha20.
- [ ] **PR 5.4 Live ALB verification (opt in) and documentation.** `tests/policy_alb_live.rs` runs only when `DCERT_LIVE_ALB_TLS13_1_3_PQ_URL` and `DCERT_LIVE_ALB_TLS13_1_2_RES_PQ_URL` are set, otherwise it is skipped with a message. Add `docs/testing/aws-alb-policy-fixtures.md` with Terraform in `infra/test-alb/` (one ALB, two HTTPS listeners on 443 and 8443 with the two policies, an ACM certificate, a fixed response action, tags for cleanup) and a Makefile target that applies it, runs the live tests, and destroys it. A manual CI workflow `live-alb.yml` (`workflow_dispatch`, uses OIDC to assume a role; no secrets in the repo) runs the same. README section "Testing against AWS security policies" with examples for both policies.

Exit criteria: the eight hermetic tests pass on both OpenSSL 3.0 and vendored 3.6 CI jobs; `dcert policy test` is available in CLI, MCP and the Python typed layer; the catalogue has a retrieval date for every entry.

---

## 9. Phase 6: knowledge base accuracy and coverage

- [ ] **PR 6.1 Correct what is wrong.** Replace `--tls-version` with `--min-tls`/`--max-tls`, `--ciphers` (as selector) with `--cipher`, `--http1.1` with `--http-protocol http1-1` in every remediation. `reference.yaml` origin TLS topic and the 502 cause: CloudFront negotiates TLS 1.3 to origins by default since 2025-11-20 (cite the AWS What's New post). `tls.handshake.protocol-version`: say that TLS 1.0 and 1.1 are rejected by the policies most services default to, and name the policies that still allow them. `apigateway.tls.security-policy`: CBC statement limited to the enhanced policies. Split `certificate_unknown` from `unknown_ca`. `tls.handshake.sni-required`: drop `tlsv1 alert internal error` or move it to a lower weight signal with its own explanation. `mtls.server.certificate-required`: TLS 1.3 server aborts the handshake after the client's Finished (RFC 8446 section 4.4.2.4) and cite RFC 5246 section 7.4.6 for TLS 1.2. `interception.vendor-ca`: qualify the mTLS statement. Remove the `X25519Kyber512Draft00` to `X25519MLKEM768` mapping note or label the security level difference. Every change cites its source and SOURCES.md is updated in the same PR.
- [ ] **PR 6.2 Evidence and signal kinds.** Extend `Evidence` with `tls_cipher` (all notations), `tls_group`, `key_exchange_class`, `pq_probe`, `client_auth` (four states), `acceptable_client_cas`, `tls_alert` (parsed from the OpenSSL error into `{level, code, name}` using a table of RFC 8446 alert names; prefix agnostic), `transport` (`direct`, `proxy`, `starttls:<proto>`), `peer_address`, `policy_report` (when `policy test` ran). Fix the path split: on a default mode verification failure, `from_error` also carries the captured chain, root class and verify details so chain based entries can fire. Add signal kinds `cipher` (pattern or `in: [..]`), `group` (pattern), `key_exchange_class` (`is`), `pq_probe` (`is`), `client_auth` (`is`), `acceptable_ca` (pattern), `tls_alert` (`name` or `code`), `transport` (`is`), `chain_error` (pattern), `policy_check` (`id`, `outcome`). Set `additionalProperties: false` on every signal variant in the schema (use `deny_unknown_fields` on each variant struct instead of on the flattened enum). Regenerate `kb/diagnostics.schema.json`. Tests for each kind.
- [ ] **PR 6.3 ALB and NLB platform and entries.** New platforms `aws_alb` (fingerprints: `server: awselb/2.0`, host `.elb.amazonaws.com` or `.elb.<region>.amazonaws.com`, chain subject patterns, ALB specific 460, 463, 464, 561 bodies) and `aws_nlb` (host `.elb.<region>.amazonaws.com` with no HTTP response and TLS only evidence) and category `elb`. New diagnostics entries, each with AWS references: `alb.tls.security-policy-rejected-version`, `alb.tls.security-policy-rejected-cipher`, `alb.tls.pq-group-not-negotiated`, `alb.mtls.verify-rejected` (handshake aborted after the client certificate; map to the connection log codes and tell the user which log field to read), `alb.mtls.passthrough-forwarded` (headers present, target rejected), `alb.mtls.ca-not-advertised`, `alb.http.460`, `alb.http.463`, `alb.http.464`, `alb.http.561`, `alb.http.502-target`, `nlb.tls.policy-rejected`. `reference.yaml` gains services `alb` and `nlb` with statuses, headers (`X-Amzn-Mtls-Clientcert*`, `X-Amzn-Trace-Id`), the `tls_verify_status` codes table and topics `alb-security-policies` (links the catalogue), `alb-mtls-modes`, `alb-connection-logs`, `nlb-tls-listeners`. `dcert kb explain ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` resolves to the catalogue entry. The `mtls.viewer.*` gate changes from `[aws_cloudfront, aws]` to `[aws_cloudfront]` so ALB mTLS refusals get ALB advice.
- [ ] **PR 6.4 Handshake and mTLS coverage, vendor neutral.** Entries for `insufficient_security`, `no_application_protocol` (ALPN rejected, uses the `alpn` and `tls_alert` signals), `illegal_parameter`, `decode_error`, `unexpected_eof` (server closed during handshake, common with SNI based routers and WAF drops), `tls.handshake.group-mismatch` (uses `pq_probe` and `tls_alert`, explains HelloRetryRequest and the ML-KEM requirement), `tls.handshake.wrong-version-number-no-proxy` (plaintext port, no proxy configured; stops the captive portal misattribution), `tls.handshake.renegotiation-disabled`, `tls.handshake.cert-name-mismatch` (vendor neutral), `mtls.client.chain-incomplete` (uses `acceptable_ca` and the client chain depth), `mtls.client.eku-missing-clientauth` (dcert inspects the configured client certificate before the handshake and records it as evidence), `mtls.client.ca-not-in-acceptable-list`, `mtls.server.bad-certificate-without-identity` (server answers a missing certificate with `bad_certificate`), `starttls.*` entries for SMTP, IMAP, POP3 and FTP failures, `tls.ocsp-stapling-required`. Local configuration errors (`no cipher match`, `no protocols available`) become a `local.config.*` layer attributed to the client, not the server.
- [ ] **PR 6.5 Sources discipline.** `kb/SOURCES.md` becomes `kb/sources.yaml` (url, title, service, retrieved, used_by entry ids) rendered to `SOURCES.md` by `scripts/render_sources.py`; a test fails when an entry cites a URL not in `sources.yaml` or when a source is unused; `dcert kb validate` checks that every CLI flag named in remediation text exists in `Cli::command()`; a CI job runs a link check monthly (`workflow_dispatch` and `schedule`), opening an issue on dead links. Add RFC 10024, RFC 8446 alerts, the ALB pages from section 1.2, and the OpenSSL security level page.

Exit criteria: `dcert diagnose` against the PR 5.3 emulated ALB with a wrong cipher offered yields `alb.tls.security-policy-rejected-cipher` as the primary finding; every entry cites a listed source; schema rejects unknown fields.

---

## 10. Phase 7: CLI, MCP and Python parity

- [ ] **PR 7.1 Every probe tool takes `TlsOptions` and `ConnectionOptions`.** `analyze_certificate`, `check_expiry`, `check_revocation`, `tls_connection_info`, `export_pem`, `diagnose_endpoint`, `validate_certificate`, `verify_key_match` (HTTPS targets) and `compare_certificates` (per target `a` and `b` options) all flatten both. Add `expired_only`, `body_limit`, `no_diagnose`, `kb_file` (validated with `validate_path`), `sort_expiry`, `data_file`, `issuer_timeout`, `no_trust_check`, `resolve_issuers`, `refresh_public_roots` where the CLI has them. `compare_certificates` runs the CLI `--diff` so both surfaces produce the same diff structure. `--watch` stays CLI only (documented). `format` stays JSON in MCP (documented).
- [ ] **PR 7.2 Knowledge base tools.** MCP `kb_list`, `kb_show`, `kb_validate` (content passed inline, no file), `kb_schema`, `kb_topics`; rename `explain_edge_term` to `kb_explain` with the old name kept as a deprecated alias for two releases. Each mirrors the CLI subcommand one to one.
- [ ] **PR 7.3 Python typed layer covers every tool.** Generate `python/src/dcert/tools.py` and `python/src/dcert/_schemas.py` from the Rust server's `tools/list` output with `scripts/gen_python_tools.py` (click; run in CI, fails when stale). `ConnectionOptions` and a new `TlsOptions` TypedDict carry every key. `TOOL_FUNCTIONS` equals the server's tool list, asserted by a test that starts the Rust binary and compares names and property sets. Python README regenerated section.
- [ ] **PR 7.4 Kiro and Kiro CLI MCP registration from the Python package.** Constraint, stated plainly in `python/README.md`: pip installs the `dcert` wheel without running any code (PEP 517 wheels have no post install hook), so registration cannot literally run inside `pip install`. The package therefore registers at the two moments it does run: `dcert-python --setup` (the documented post install step that also downloads the binary) and the first start of `dcert-python`. Trigger condition, the only one: the directory `~/.kiro` exists. Implementation in `python/src/dcert/kiro.py`, pure functions, no classes, configuration in `config.yaml` under `kiro:` (file name, server key, entry template, auto register flag, backup retention).
  - Target file: `~/.kiro/settings/mcp.json`, read by Kiro IDE and Kiro CLI. Desired entry under `mcpServers.dcert`: `{"command": "<absolute path of the dcert-mcp console script in the same bin directory as sys.executable, or the bare name dcert-mcp when not found>", "args": [], "env": {}, "disabled": false, "autoApprove": []}`, so a virtual environment install works when Kiro's `PATH` lacks the venv.
  - Decision table (`plan(home, desired) -> Plan`): no `~/.kiro` directory: `no_kiro`, nothing happens. File absent: `create`. File present and `mcpServers.dcert` present and correct (command resolves to an existing executable, `disabled` is false): `unchanged`, nothing is written, no backup, no log noise beyond one debug line. Entry present but incorrect (command missing on disk or pointing at another interpreter's stale script): `repair`, which rewrites only the `command` field and nothing else. Entry absent: `add`. File not valid JSON, or `mcpServers` not an object: `refuse`, file untouched, message names the file and the parse error. Every outcome is an enum value returned to the caller and printed by the CLI.
  - Change control for every write: compute the new document in memory; show a unified diff of old and new text (`--kiro-status --diff`, and always in `--setup` output); `--dry-run` prints the diff and writes nothing; back up the original to `mcp.json.bak.<UTC timestamp>` beside it, keeping the five newest backups; write to a temporary file in the same directory with the original file mode, `fsync`, then `os.replace`; re read and parse the written file and verify that every pre existing key is present and unchanged and that exactly the planned change is present, otherwise restore the backup and report `verification_failed`; take an exclusive file lock on `mcp.json.lock` during the operation so two concurrent starts do not race. Preserve the other servers, key order, trailing newline and the file's indentation (detect two or four spaces). Never remove or reorder anything. Never write to stdout under the stdio transport; all messages go to stderr.
  - `unregister(home, dry_run)`: removes only the `dcert` key, same safety rules; `status(home)`: prints the decision table outcome and the diff that `register` would apply.
  - CLI: `dcert-python --setup` runs the registration after the binary download; new flags `--register-kiro`, `--unregister-kiro`, `--kiro-status`, `--dry-run` and `--no-kiro`. Auto registration at the first start of `dcert-python` is on by default (`kiro.auto_register: true`, override `DCERT_KIRO_AUTO_REGISTER=0`), applies the same decision table, and never aborts the server when it cannot register.
  - Documentation: `python/README.md` and the README "Claude Code / Kiro / Kiro CLI" section gain the two line install: `pip install dcert` (or `pipx install dcert`, `uv tool install dcert`) then `dcert-python --setup`, and a table of the outcomes above.
  - Tests (`python/tests/test_kiro.py`, pytest with `tmp_path` as home, one test per decision table row plus): an existing file with two other servers, four space indentation and a trailing newline keeps both servers, their order, the indentation and the newline and only gains `dcert`; a correct existing entry produces no write, no backup and no modification time change; a stale command path is repaired and only that field differs in the diff; a second run after `add` is `unchanged`; invalid JSON is untouched and reported; `dry_run` writes nothing but prints the diff; verification failure restores the backup; the lock prevents a concurrent second writer; `unregister` removes only `dcert`; the console script path is absolute when it exists in the interpreter's bin directory; auto registration is skipped with `DCERT_KIRO_AUTO_REGISTER=0`; backups are pruned to five.
- [ ] **PR 7.5 Parity gate in CI.** The Rust parity test (PR 3.2), the Python generator freshness check (PR 7.3), the defaults sync check (PR 3.4) and a README check that every `--help` flag appears in the options reference table run as one `parity` job. Any drift fails CI.

Exit criteria: the parity job is green and required; the tool table in README lists every tool with its CLI equivalent; `dcert-python --setup` on a machine with `~/.kiro` registers the server once and is a no op on every later run.

---

## 11. Phase 8: readability and documentation

- [ ] **PR 8.1 Module layout.** `src/tls.rs` splits into `tls/mod.rs` (public API), `tls/connector.rs`, `tls/handshake.rs`, `tls/http.rs` (request head and response capture), `tls/starttls.rs`, `tls/pq.rs`; `src/main.rs` command dispatch moves to `src/commands/{check,diagnose,kb,policy,ciphers,convert,csr,verify_key,vault}.rs`, each under 400 lines. No behaviour change; byte identical outputs on the fixture corpus (add `tests/snapshots/` with `insta` or a plain golden file comparison).
- [ ] **PR 8.2 Naming and docs.** Rename the ambiguous `--ciphers` to `--cipher-notation` in help (alias kept), `verify-key` to accept `--dir` as documented, and align MCP field names with CLI flag names (`headers` to `header`, `strict` to `warnings_as_errors`, `sans` to `san`, `common_name` to `cn`) with the old names accepted as aliases for two releases and a deprecation note in the tool description. Architecture document `docs/architecture.md` with one SVG diagram (draw.io source kept beside it) of the probe pipeline: options, connector, handshake, evidence, knowledge base scoring, policy engine, output.
- [ ] **PR 8.3 Release notes.** Collapse the `Unreleased` CHANGELOG entries into a `3.1.0` summary grouped by phase, update README quick start with `dcert policy test` and `dcert ciphers`, update `SECURITY.md` and `python/README.md`, and announce the exit codes 9 and 10.

Exit criteria: no source file over 1,200 lines except generated ones; golden outputs unchanged; documentation complete.

---

## 12. Scope decisions and open questions

Decided here so Claude Code does not stop to ask:

1. TLS 1.0 and 1.1 support is probe only, opt in, and never a default.
2. The cipher table is generated and committed, never fetched at build time (hermetic builds).
3. The policy catalogue is data in `kb/`, merged at runtime with `--policy-file` like `--kb-file`, so a team can add an internal policy without a release.
4. ALB policies whose classical groups AWS does not document are tested only for the documented hybrid groups plus `X25519` as the classical fallback; the report says so.
5. Exit codes 9 and 10 are new; existing codes are unchanged.
6. The Linux glibc floor stays Ubuntu 22.04; ML-KEM group naming on OpenSSL 3.5 hosts is solved with runtime symbol resolution (PR 2.6), not by raising the floor.
7. `--watch` and `--format` are intentionally CLI only in MCP.
8. Kiro registration runs from `dcert-python --setup` and at first start, never through an import time or `.pth` side effect, because wheels have no post install hook and configuration must only change through an auditable, reversible, dry run capable command.

Ask Dejan before acting (stop conditions):

- PR 1.6: if implementing TLS to an `https://` proxy exceeds the PR budget, ship the rejection and record the follow up.
- PR 5.4: AWS account, region and the OIDC role ARN for the live ALB workflow.
- PR 8.2: whether to keep the deprecated MCP field aliases for two releases or remove them immediately.

---

## 13. Progress log

Keep one line per session: date, PR, state, next action.

- 2026-10-26: plan written. Next: PR 0.1.
- 2026-10-26: PR 0.1 harness implemented (`src/testutil.rs`, `tests/support/mod.rs`, `tests/tls_harness.rs`). Next: PR 0.2.
- 2026-10-26: PR 0.2 CI changes implemented (SHA pins, no `--all-features`, MSRV, pip-audit, trixie job). Next: PR 0.3.
- 2026-10-26: PR 0.3 quick fixes (a) to (g) implemented with regression tests (`tests/regressions.rs`); also fixed STARTTLS reporting `client_auth: optional` when a certificate was presented. Next: PR 1.1.
- 2026-10-26: PR 1.1 file root confinement implemented (canonical paths to the child, child cwd is the first root, temp dir no longer a default root, file targets confined). Next: PR 1.2.
- 2026-10-26: PR 1.2 Vault token fallback implemented (`AddrTrust`, `resolve_token_source`). Next: PR 1.3.
- 2026-10-26: PR 1.3 destination policy implemented (`src/netpolicy.rs`, MCP pre checks, child enforcement at dial time and for AIA). Next: PR 1.4.
- 2026-10-26: PR 1.4 Python transport auth (`dcert/auth.py`), Host header guard and passthrough list implemented. Next: PR 1.5.
- 2026-10-26: PR 1.5 secrets off argv implemented (`--headers-file`, private temp files, `hide_env_values`, masked proxy errors). Next: PR 1.6.
- 2026-10-26: PR 1.6 https proxy rejection and same origin redirects for Vault and OIDC. Follow up recorded on PR 1.6 for TLS to the proxy. Next: PR 1.7.
- 2026-10-26: PR 1.7 fail closed authorisation, OIDC hardening, per call audit, no_verify gate and TLS warning implemented. Next: PR 1.8.
- 2026-10-26: PR 1.8 supply chain (attestations, cosign, SHA256SUMS, SBOM asset, Trivy image scan, SECURITY.md). Next: phase 1 exit check, then PR 2.1.
- 2026-10-26: PR 2.1 deadlines implemented (`src/deadline.rs` watchdog, write timeouts, STARTTLS caps, drip tests in `tests/deadlines.rs`). Next: PR 2.2.
- 2026-10-26: PR 2.2 DNS (`src/dns.rs`: bounded lookup, every address tried, all attempts reported). Next: PR 2.3.
- 2026-10-26: PR 2.3 OCSP through the proxy with `--timeout`, AIA issuers verified. Next: PR 2.4.
- 2026-10-26: PR 2.4 input ranges (`src/limits.rs`), bounded semaphore wait, mode validation, 10 s drain deadline. Next: PR 2.5.
- 2026-10-26: PR 2.5 install record and 0700 install directory. Next: PR 2.6.
- 2026-10-26: PR 2.6 runtime `SSL_get0_group_name` via dlsym, build header version in `--version`, trixie job required. Next: PR 2.7.
- 2026-10-26: PR 2.7 IMAP tagged reply reader and Windows Ctrl+Break, close and shutdown handling. Next: phase 2 exit check, then PR 3.1.
- 2026-10-26: PR 3.1 `TlsOptions`, `ConnectionOptions` and `ProbeOptions` in `src/tlsopts.rs`; `check` and `verify-key` share them, `--cipher-notation` with `--ciphers` as alias. Serde and JSON schema derives arrive with PR 3.2, where the MCP layer starts using the types. Next: PR 3.2.
- 2026-10-26: PR 3.2 `ToCliArgs`/`ArgBuilder` serialiser with `--flag=value`, `ProbeParams` for the seven probe tools, parity test with a `CLI_ONLY` list; found and fixed upper case `method` being rejected. The MCP parameter types keep their own fields until PR 7.1 flattens `TlsOptions` into them, so `TlsOptions` stays clap only for now. Next: PR 3.3.
