# dcert security and dependency minimization plan (section set S)

Plan for Claude Code. Repository: `SCGIS-Wales/dcert`, branch `main`, commit `2ab66cb`, version `3.0.80`.
Author: Dejan Gregor. Written 2026-11-20 from measurements taken that day against the real lock file and the live advisory databases.

This document is the security half of the PyPI split plan (`docs/plans/2026-11-pypi-split-dcert-mcp.md`). It states why the split exists, lists every known vulnerability with its fix, and defines the phases (S0 to S7) that interleave with the packaging phases. Place it at `docs/plans/2026-11-dcert-security-dependency-minimization.md` until the two documents are merged.

`CLAUDE.md` applies in full: every commit is authored by `api-py`, with no `Co-Authored-By` trailer and no AI attribution in commits, pull requests or release notes. Every merge to `main` is a release, so every pull request below must be small and shippable.

---

## 1. Why this work exists

The split into `dcert` and `dcert-mcp` has one purpose: `dcert` must carry the minimum possible set of dependencies, because the current single package inherits every vulnerability of the MCP stack.

Measured on 2026-11-20:

| Finding | Value | How measured |
| --- | --- | --- |
| Python packages installed by `pip install dcert` today | 62 | `uv pip compile` of the three runtime requirements for Python 3.12 |
| Of those 62, packages with advisories published against the version current on 2026-05-20 | 15 | PyPI advisory data per release |
| Advisory records behind that figure | 104 records, about 60 distinct issues | Same source, deduplicated by CVE |
| Known vulnerabilities in the Python tree at today's latest versions | 0 | `pip-audit` 2.10.1 |
| Rust crates both binaries are built against today | 257 | `cargo tree -e normal`, Linux x86_64 |
| Rust vulnerabilities in `Cargo.lock` today | 3 (two ignored, one new) | `cargo audit` 0.23.0, advisory database of 2026-11-19 |
| Rust vulnerabilities after the upgrades in phase S1 and S2 | 0 | Same command on the upgraded lock file |
| Rust crates in the `dcert` CLI after the feature split in phase S3 | 166 (156 without Excel export) | `cargo tree -e normal` on the split manifest |
| OpenSSL statically linked into the Windows binaries | 3.6.3, a branch that is out of support | `openssl-src 300.6.1+3.6.3` in `Cargo.lock` |

Three conclusions follow.

1. The Python tree is clean today only because it floats to the latest release. In six months it produced about 60 distinct advisories. A zero dependency `dcert` wheel removes that exposure completely.
2. The Rust side has one live unpatched advisory (`rmcp`, published 2026-11-05, after the last dependency refresh) and two ignored advisories. All three reach only the MCP server, yet today they are compiled into the audit scope of the CLI as well.
3. The Windows build ships an OpenSSL branch that no longer receives fixes. This needs its own remediation.

## 2. Security objectives and targets

| Id | Objective | Target | Proof |
| --- | --- | --- | --- |
| O1 | `dcert` wheel has no Python dependencies | 0 `Requires-Dist` lines | Wheel metadata test in CI |
| O2 | `dcert` launcher uses the standard library only and never opens a network connection | No third party import, no `urllib` | Import test in CI |
| O3 | `dcert` CLI binary excludes every MCP only crate | 0 banned crates in the CLI tree, at most 170 crates | `scripts/check_cli_deps.py` in CI |
| O4 | No ignored advisory anywhere | Empty `ignore` lists in `.cargo/audit.toml` and `deny.toml` | `cargo audit`, `cargo deny` |
| O5 | No known unpatched vulnerability in either distribution at release | 0 findings | `cargo audit`, `cargo audit bin`, `uv audit`, `pip-audit`, Trivy |
| O6 | Every shipped binary declares its exact dependency list | `cargo auditable` data present in all eight binaries | `cargo audit bin` in CI |
| O7 | Linked OpenSSL is a supported branch at its newest patch release | Floor recorded in YAML and checked per artefact | `dcert --version` gate |
| O8 | New advisories are detected between merges | Daily scheduled audit that fails visibly | `audit.yml` workflow |
| O9 | Evidence is published | One SBOM per binary and per wheel, attested | Release assets |

An exception to O4 or O5 is allowed only when no upstream fix exists. It must carry an owner, a reason and an expiry date no more than 30 days ahead, and CI must fail once the date passes.

## 3. How the measurements were made

Run these again at execution time. The numbers in this plan are a starting point. The commands are authoritative.

```bash
# Step 1: install the audit tools at the versions used for this plan. Next: Rust audit.
cargo install --locked cargo-audit@0.23.0 cargo-deny@0.22.0 cargo-auditable@0.7.7 cargo-cyclonedx@0.5.10

# Step 2: audit a copy of the lock file outside the repository, so the ignore list in .cargo/audit.toml
#         does not apply and ignored advisories are visible. Next: count crates.
AUDIT_DIR="$(mktemp -d)" && cp Cargo.lock "$AUDIT_DIR/" && (cd "$AUDIT_DIR" && cargo audit --file Cargo.lock)

# Step 3: count the unique crates a build uses (add --features mcp or --no-default-features after phase S3).
#         Next: Python tree.
cargo tree --locked -e normal --prefix none | sed 's/ (\*)//' | sort -u | wc -l

# Step 4: resolve the full Python runtime tree exactly as pip would today. Next: audit it.
printf 'fastmcp>=4.1.6,<5\nclick>=8.5,<9\npyyaml>=6.0.3,<7\n' > /tmp/req.in
uv pip compile /tmp/req.in --python-version 3.12 -o /tmp/req.txt

# Step 5: audit the resolved tree against the PyPI advisory service. Next: audit the lowest allowed versions.
uvx pip-audit -r /tmp/req.txt --no-deps --disable-pip --progress-spinner off

# Step 6: audit the lowest versions the declared ranges allow, which is what an old cache or mirror may serve.
#         Next: record all outputs under docs/security/baseline/ (phase S0).
uv pip compile /tmp/req.in --python-version 3.12 --resolution lowest-direct -o /tmp/req-lowest.txt
uvx pip-audit -r /tmp/req-lowest.txt --no-deps --disable-pip --progress-spinner off
```

Limits of the evidence, stated plainly:

- The crate counts for the feature split come from the real `Cargo.toml` and `Cargo.lock` with stub source files, so they prove what Cargo resolves but not that the code compiles. Phase S3 does the code changes.
- The upgrade of `jsonwebtoken` from 11 to 12 and of `rmcp` from 3.8 to 3.11 was resolved and audited, not compiled. Their API changes must be handled in S1 and S2.
- GitHub Actions advisories could not be queried through the GitHub API from the analysis environment. Section 4.4 gives the command to run.

## 4. Vulnerability inventory (2026-11-20)

### 4.1 Rust crates

| Advisory | Crate and locked version | Severity | Reaches | Fix | Phase |
| --- | --- | --- | --- | --- | --- |
| `RUSTSEC-2026-0462` (GHSA-c9f9-cp8h-jcj5), unbounded response body buffering in Streamable HTTP clients | `rmcp 3.8.0` | Medium (6.5) | `dcert-mcp` only | Upgrade to `rmcp 3.11.0` (patched from 3.9.0). **Not ignored, so `cargo audit` fails on the next push to `main` and blocks the release pipeline.** | S1 |
| `RUSTSEC-2023-0071` (CVE-2023-49092), Marvin attack timing side channel | `rsa 0.9.10` through `jsonwebtoken 11.1.0` | Medium (5.9) | `dcert-mcp` only. Ignored today. | Move `jsonwebtoken` to 12 with the `aws_lc_rs` backend. `rsa` leaves the tree. | S2 |
| `RUSTSEC-2026-0387`, timing variability in constant time operations | `crypto-bigint 0.5.5` through `p256` and `p384` 0.13 | Not scored | `dcert-mcp` only. Ignored today. | Same change. `crypto-bigint` leaves the tree. | S2 |
| `RUSTSEC-2026-0543`, crate is unmaintained (informational) | `chrono 0.4.45` through `rmcp` and `schemars` | Warning | `dcert-mcp` only after S3 | No fixed release exists. Removed from the CLI by the feature split. Track upstream `rmcp` and `schemars` for a move to `jiff` or `time`. | S3, watch |

Earlier `rmcp` advisories (`RUSTSEC-2026-0189`, `0457`, `0461`) are already fixed in 3.8.0.

Verified result: with `rmcp = "3.11"` and `jsonwebtoken = { version = "12", features = ["aws_lc_rs"] }` followed by `cargo update`, `cargo audit` reports 0 vulnerabilities and the lock file falls from 346 to 313 packages. `aws-lc-rs` is already in the tree through `rustls`, so the new backend adds no new cryptographic library.

### 4.2 OpenSSL

| Build | OpenSSL in use | Status | Action |
| --- | --- | --- | --- |
| Windows (`vendored`, static) | 3.6.3 from `openssl-src 300.6.1+3.6.3` | The 3.6 branch is out of support. Releases 3.6.4 (25 August 2026) and 3.6.5 (29 September 2026) are not packaged by `openssl-src`, and the advisories of 10 and 17 November 2026 no longer assess or fix the 3.6 branch. | Phase S4 |
| Linux release binaries | System OpenSSL 3.0, linked dynamically at run time | Patched by the host distribution. Upstream 3.0 fixes are now for premium support customers only, so the distribution is the only source of fixes. | Document in `SECURITY.md` |
| Docker image | OpenSSL 3.5 from Debian trixie | Supported long term branch. 3.5.10 is scheduled for 1 December 2026. | Refresh base digest in S1 and after 1 December |
| macOS | Homebrew `openssl@3` at build time | Not verified whether linked statically or dynamically. | Verify in S4 with `otool -L` |
| CI job `test-post-quantum` | Vendored 3.6.3 | Test only, never shipped. | Follows S4 |

Constraint found: `openssl-sys 0.9.118` requires `openssl-src ^300.2.0`, so the OpenSSL 4.0 packages (`400.0.2+4.0.3`) cannot be selected, and the newest 3.5 package is `300.5.5+3.5.5`, which is older still. The vendored route therefore cannot reach a patched release today.

The issues fixed in 3.6.4 and 3.6.5 that are not confined to DTLS, QUIC, CMS, CMP or TLS servers are all rated Low: `CVE-2026-35189` (memory allocation in relative CRL distribution point processing, which a certificate parser can reach), `CVE-2026-75803` (AEAD with empty ciphertext through `EVP_Cipher`) and `CVE-2026-54872` (timing in scalar multiplication on some curves). The High and Moderate items for the 3.6 branch concern DTLS, QUIC, CMS and CMP, which dcert is not expected to use. Confirm that in S4 with `grep -rniE 'cms|pkcs7|dtls|quic' src/`.

### 4.3 Python packages

At the latest resolvable versions the runtime tree (62 packages), the tree with the `otel` extra (71) and the tree with development tools (124) all report no known vulnerabilities. The lowest versions the current ranges allow (`fastmcp 4.1.6`, `click 8.5.0`) are also clean.

The exposure is the rate of change. Advisories published against the versions that were current six months ago, with the first patched release of each:

| Package | Distinct advisories | First fully patched release | Resolved today |
| --- | --- | --- | --- |
| `pyjwt` | 16 | 2.15.1 (verify, one record has no fixed version listed) | 2.15.1 |
| `authlib` | 9 | 1.9.1 | 1.9.9 |
| `mcp` | 8 | 2.2.0 | 2.3.0 |
| `starlette` | 5 | 1.3.1 | 1.10.0 |
| `cryptography` | 4 | 50.0.0 | 50.0.2 |
| `joserfc` | 4 | 1.7.6 | 1.8.0 |
| `httpx2` | 3 | 2.12.0 | 2.16.2 |
| `python-multipart` | 3 | 0.0.31 | 0.0.34 |
| `anyio` | 2 | 4.14.2 | 4.16.0 |
| `dnspython` | 2 | 2.9.2 | 2.9.2 |
| `opentelemetry-api` | 2 | 1.45.2 | 1.45.2 |
| `certifi` | 1 | 2026.10.18 | 2026.10.23 |
| `fastmcp` | 1 | 4.1.2 | 4.2.3 |
| `httpcore2` | 1 | 2.10.0 | 2.16.2 |
| `pydantic-settings` | 1 | 2.14.2 | 2.16.3 |

None of these packages will be installed by `dcert` after the split. They remain relevant only to the Python proxy in `dcert-mcp` (section 5.5).

There is no lock file for Python today. CI audits whatever resolves on the day, and nothing fails between merges when a new advisory appears. Phases S5 and S6 close both gaps.

### 4.4 GitHub Actions

Every action is pinned by commit SHA, which is the control that protected pinned users during the March 2026 Trivy tag compromise (`CVE-2026-33634`). `aquasecurity/trivy-action` is pinned at v0.36.0, which is later than the first safe release, v0.35.0.

Two gaps remain. The Trivy scanner binary that the action downloads is not pinned, and no linter checks the workflows. Phase S6 adds both. Advisory status for the other actions was not verified. Run this at execution time:

```bash
# Step 1: lint every workflow, including the online check for actions with published advisories.
#         Next: fix each finding or record why it is accepted.
uvx zizmor@1.32.0 --gh-token "$(gh auth token)" .github/workflows/
```

### 4.5 Container image

`debian:trixie-slim` is pinned by digest and scanned by Trivy on every run with `ignore-unfixed: true`. Unfixed findings are therefore invisible. Phase S6 adds a second, report only scan without that flag.

## 5. Target design

### 5.1 `dcert` wheel: zero dependencies, enforced

- `dependencies = []` in `python/dcert/pyproject.toml`. No extras.
- The wheel contains the `dcert` binary and at most a standard library launcher. `download.py`, `checksums.json`, `config.py` and `config.yaml` do not ship in `dcert`. The package performs no network access.
- Preferred layout, to be settled with the packaging plan: place the native executable in the wheel `.data/scripts` directory, as `ruff` and `uv` do, so that no Python code runs when the user types `dcert`. If a Python launcher is kept, it may import only standard library modules.
- Constants the launcher needs (environment variable names) live in one generated module, written from the YAML source by a script and checked in CI, because the launcher cannot read YAML without a dependency.

Permanent tests (phase S5):

```python
# tests/test_wheel_contract.py (sketch): fails when the built dcert wheel gains a dependency.
import sys


def test_dcert_wheel_has_no_dependencies(dcert_wheel_metadata: str) -> None:
    assert "Requires-Dist:" not in dcert_wheel_metadata


def test_launcher_imports_stdlib_only(launcher_modules: frozenset[str]) -> None:
    assert launcher_modules <= sys.stdlib_module_names
```

### 5.2 `dcert` CLI binary: Cargo feature split

One package and one repository stay as agreed. The MCP only crates become optional behind an `mcp` feature, and the `dcert-mcp` binary requires that feature.

Crates used only under `src/mcp/`: `rmcp`, `tokio`, `jsonwebtoken`, `axum`, `tower-http`, `tower`, `tracing`, `tracing-subscriber`, `tokio-util`, `subtle`. `schemars` is also used by four shared files (`src/tlspolicy/mod.rs`, `src/kbref.rs`, `src/mtls.rs`, `src/diagnose.rs`) to derive schemas that only the MCP layer consumes, so those derives become conditional.

Proposed `Cargo.toml` changes, shown in full for the parts that change:

```toml
[[bin]]
name = "dcert"
path = "src/main.rs"

[[bin]]
name = "dcert-mcp"
path = "src/mcp/main.rs"
required-features = ["mcp"]

[dependencies]
# MCP server only. Optional so the dcert CLI is built and audited without them.
rmcp = { version = "3.11", features = ["server", "transport-io", "transport-streamable-http-server", "client"], optional = true }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "process", "io-std", "sync", "time", "signal"], optional = true }
jsonwebtoken = { version = "12", features = ["aws_lc_rs"], optional = true }
axum = { version = "0.8", optional = true }
tower-http = { version = "0.7", features = ["cors", "limit", "timeout", "trace"], optional = true }
tower = { version = "0.5.3", features = ["limit", "timeout", "util"], optional = true }
tracing = { version = "0.1", optional = true }
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"], optional = true }
tokio-util = { version = "0.7.20", optional = true }
subtle = { version = "2.6", optional = true }
schemars = { version = "1.2", optional = true }
# Excel export for `dcert vault list`. On by default, removable for a smaller build.
rust_xlsxwriter = { version = "0.103", optional = true }

[features]
default = ["xlsx"]
# Everything the dcert-mcp binary needs.
mcp = [
    "dep:rmcp", "dep:tokio", "dep:jsonwebtoken", "dep:axum", "dep:tower-http", "dep:tower",
    "dep:tracing", "dep:tracing-subscriber", "dep:tokio-util", "dep:subtle", "dep:schemars",
]
xlsx = ["dep:rust_xlsxwriter"]
vendored = ["openssl/vendored"]
```

Source changes that go with it:

- In the four shared files, replace `#[derive(JsonSchema)]` with `#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]` and gate the `use schemars` lines and any `#[schemars(...)]` attributes the same way.
- Gate the Excel export in `src/vault.rs` with `#[cfg(feature = "xlsx")]` and return a clear error when the feature is off.
- Move `wiremock` behind the same condition in tests, or run those tests only with `--features mcp`.

Measured effect on Linux x86_64 (normal dependencies, unique crates, root crate included):

| Build | Before | After S1 and S2 | After S3 |
| --- | --- | --- | --- |
| `dcert-mcp` (`--features mcp`) | 257 | 226 | 226 |
| `dcert` (default features) | 257 | 226 | 166 |
| `dcert` (`--no-default-features`) | 257 | 226 | 156 |

After S3 the CLI tree contains none of `rmcp`, `axum`, `jsonwebtoken`, `rsa`, `crypto-bigint` or `chrono`. `tokio`, `hyper`, `rustls` and `aws-lc-rs` remain in the CLI through `reqwest`, whose subtree is about 92 crates. Reducing that is optional phase S4b.

Consequences that must be handled in the same pull request:

1. **A plain `cargo build --release` will silently stop producing `dcert-mcp`.** Every build that ships both binaries must build them in two steps, and copy each binary aside straight after its own build:

   ```bash
   # Step 1: build the CLI with its own minimal dependency list embedded. Next: copy it aside.
   cargo auditable build --release --locked --bin dcert
   cp target/release/dcert dist/dcert

   # Step 2: build the MCP server with the mcp feature. Next: copy it aside and package both.
   cargo auditable build --release --locked --bin dcert-mcp --features mcp
   cp target/release/dcert-mcp dist/dcert-mcp
   ```

   Building both in one command with `--features mcp` would compile the shared library with the feature on, and the CLI would then declare the MCP crates in its embedded dependency list.
2. Jobs to change in `.github/workflows/ci.yml`: `test`, `msrv`, `pq-shipped-binary`, `test-post-quantum`, `security-audit`, `integration-test`, `build-linux`, `build-macos-intel`, `build-macos-arm`, `build-windows`. Tests, Clippy and the MSRV check run twice, once per feature set.
3. The local gate in `CLAUDE.md` and in the plan gains the second feature set.
4. Homebrew, Chocolatey, Docker and the release archives are unaffected in content, because they consume the packaged archive, which still holds both binaries. The README states that Homebrew on Linux builds from source, but the generated formula installs prebuilt archives. Correct the README in the documentation pull request.
5. `Cargo.lock` still lists optional crates. Repository level scanners (Dependabot alerts, Trivy filesystem scans, the GitHub dependency graph) will keep reporting MCP only crates against the repository. The evidence for the CLI is therefore taken from the binary: `cargo audit bin`, the embedded `cargo auditable` data and one SBOM per binary. `SECURITY.md` must explain this in two sentences.

A Cargo workspace with two packages was considered and rejected for now. It shares the same single `Cargo.lock`, so it gives scanners nothing the feature split does not, and it contradicts the agreed scope of one crate.

### 5.3 JWT verification without the ignored advisories

Change `jsonwebtoken` to version 12 with the `aws_lc_rs` feature in place of `rust_crypto`. Version 12 also moves its RustCrypto path to `rsa 0.10` and `p256`/`p384` 0.14, so either backend clears both advisories. `aws_lc_rs` is preferred because it removes the RustCrypto asymmetric crates entirely and reuses a library already linked through `rustls`.

Then delete both entries from `.cargo/audit.toml` and `deny.toml`. Target state for both files:

```toml
[advisories]
ignore = []
```

Check the `jsonwebtoken` 12 changelog for API changes in `src/mcp/security/oidc.rs`, and keep the existing OIDC tests (RS256, ES256, ES384, expired token, wrong audience, wrong issuer, unknown key id) passing unchanged.

### 5.4 OpenSSL on Windows

Choose at execution time, in this order, and stop at the first that works:

1. If a newer `openssl-sys` accepts `openssl-src 400.x`, or `openssl-src` has published a patched 3.5 release, stay vendored and pin that release with `cargo update -p openssl-src --precise <version>`.
2. Otherwise link a maintained static OpenSSL from vcpkg on the Windows runner (`vcpkg install openssl:x64-windows-static-md`, `OPENSSL_STATIC=1`, `OPENSSL_DIR` pointing at the vcpkg tree) and remove the Windows only `vendored` target dependency. Verify the vcpkg port version first.
3. If neither is possible, record a dated exception under objective O7 and check again weekly through the scheduled audit.

Whatever is chosen, add a gate: `scripts/openssl_floor.yaml` records the minimum acceptable version per branch (today 3.5.9 and 4.0.3, rising to 3.5.10 and 4.0.4 on 1 December 2026), and CI runs `dcert --version` on each built artefact and fails below the floor.

### 5.5 `dcert-mcp`: keep the default install minimal too (decision for Dejan)

The Rust `dcert-mcp` binary is a complete MCP server on its own. The Python FastMCP proxy and typed client are an additional layer, and they are the only reason 62 Python packages are installed.

Recommendation: make the proxy an optional extra.

| Install command | What it provides | Third party Python packages |
| --- | --- | --- |
| `pip install dcert` | `dcert` CLI | 0 |
| `pip install dcert-mcp` | `dcert` CLI and the `dcert-mcp` Rust MCP server | 0 |
| `pip install "dcert-mcp[proxy]"` | The above plus the FastMCP proxy, typed client and proxy command | 62 |
| `pip install "dcert-mcp[proxy,otel]"` | The above plus OpenTelemetry export | 71 |

What this changes: the proxy command and `import dcert_mcp` helpers that need FastMCP must fail with one clear line naming the extra when it is missing; tests run with the extra installed; the README gains the table above. `fastmcp-slim` was evaluated as a lighter base and gives no saving, because the proxy needs both its `client` and `server` extras, which resolve to 61 packages.

This alters the earlier assumption that `pip install dcert-mcp` always includes the proxy. **Stop condition: confirm with Dejan before starting S5.2.** If he declines, S5.2 keeps FastMCP as a hard dependency of `dcert-mcp` and everything else in this plan still applies.

In either case the proxy requirements carry security floors, so no resolver can select a release with a known advisory:

```toml
[project.optional-dependencies]
proxy = [
    "fastmcp>=4.2.3,<5",
    "click>=8.5.1,<9",
    "pyyaml>=6.0.3,<7",
    # Security floors for transitive packages: first release with every advisory in section 4.3 fixed.
    "mcp>=2.3.0",
    "starlette>=1.3.1",
    "authlib>=1.9.1",
    "pyjwt>=2.15.1",
    "cryptography>=50.0.0",
    "joserfc>=1.7.6",
    "httpx2>=2.12.0",
    "httpcore2>=2.10.0",
    "python-multipart>=0.0.31",
    "anyio>=4.14.2",
    "dnspython>=2.9.2",
    "certifi>=2026.10.18",
    "pydantic-settings>=2.14.2",
    "opentelemetry-api>=1.45.2",
]
```

A CI job resolves these with `--resolution lowest-direct` and audits the result, which proves the floors are sufficient.

### 5.6 Dependabot

Add entries for both new Python project directories. Use the `uv` ecosystem for the committed `uv.lock`, limited to security updates, because its version updates rewrite lower bounds and its lock file only mode is unreliable. Routine refreshes come from the scheduled workflow in S6, which runs `uv lock --upgrade` and opens one pull request. CI runs `uv lock --check` so a stale lock fails fast.

## 6. Phases

One pull request per checkbox. Branch name `plan/S<phase>-<n>-<slug>`. Each pull request updates `CHANGELOG.md` under `Unreleased` and ticks its own box. Never merge red.

### Phase S0: baseline

- [ ] **S0.1 Capture the before snapshot.**
  - Scope: run section 3 and store the raw outputs under `docs/security/baseline/2026-11/` (`cargo-audit.txt`, `cargo-tree-count.txt`, `pip-audit.txt`, `python-tree.txt`, `trivy.txt`). No code change.
  - Acceptance: files committed; figures match section 1 or the differences are explained in the pull request body.
  - Rollback: revert the commit.
  - Session notes:

### Phase S1: patch by upgrade alone (before the split)

- [x] **S1.1 Rust: clear the live `rmcp` advisory and refresh every crate.**
  - Scope: `rmcp` to 3.11; `rust_xlsxwriter` to 0.103; `cargo update`; adapt to any API change.
  - Commands:

    ```bash
    # Step 1: list what is behind, including incompatible upgrades. Next: apply compatible ones.
    cargo update --dry-run --verbose

    # Step 2: apply every compatible update to the lock file. Next: raise the two manifest versions by hand.
    cargo update

    # Step 3: after editing Cargo.toml (rmcp 3.11, rust_xlsxwriter 0.103), check both gates. Next: full local gate.
    cargo audit && cargo deny check
    ```

  - Acceptance: `cargo audit` and `cargo deny check` pass (the two ignored advisories stay ignored until S2; the `chrono` warning remains); all tests pass; MSRV job passes.
  - Rollback: revert; `Cargo.lock` is restored with it.
  - Session notes: Done. rmcp 3.8.0 to 3.11.0 clears RUSTSEC-2026-0462; rust_xlsxwriter 0.103; cargo update refreshed the lock. No source changes were needed. cargo deny also failed on the chrono unmaintained notice (RUSTSEC-2026-0543) before this change, so deny.toml now sets unmaintained = "workspace" (direct dependencies only) with a comment; revisit after S3.

- [x] **S1.2 Python: raise floors to patched releases.**
  - Scope: in the current `python/pyproject.toml`, raise `fastmcp` to `>=4.2.3`, `click` to `>=8.5.1`, and add the security floors of section 5.5. Development tools to latest.
  - Acceptance: `pip-audit` clean on the latest and on the `lowest-direct` resolution; tests pass on 3.12 to 3.15.
  - Rollback: revert.
  - Session notes: Done. fastmcp 4.2.3, click 8.5.1 and the section 5.5 floors are hard dependencies for now (S5.2 is blocked on confirmation). pip-audit is clean on the latest and the lowest-direct resolution (with the otel extra); ruff, mypy and pytest pass on 3.12. Not run on 3.13 to 3.15 locally; CI covers them.

- [x] **S1.3 Actions and base image.**
  - Scope: resolve each action to its newest release SHA; refresh the `debian:trixie-slim` digest; pin the Trivy binary version in the `trivy-action` step.
  - Commands:

    ```bash
    # Step 1: print the newest release tag of one action and the commit SHA it points at.
    #         Next: repeat per action, then update each pin and its version comment.
    TAG="$(gh api repos/actions/checkout/releases/latest --jq .tag_name)"
    echo "$TAG $(gh api "repos/actions/checkout/commits/$TAG" --jq .sha)"

    # Step 2: print the current digest of the base image. Next: replace the digest in Dockerfile.
    docker buildx imagetools inspect debian:trixie-slim --format '{{.Manifest.Digest}}'
    ```

  - Acceptance: CI green; Trivy job passes; no action referenced by tag.
  - Rollback: revert.
  - Session notes: Done. Every action was already at its newest release except taiki-e/install-action (v2.90.6) and github/codeql-action (v4.39.4), now bumped. The debian:trixie-slim digest is unchanged. The Trivy binary is pinned to v0.76.2 through the action `version` input; this is only proven by a CI run, so check the Trivy job on the pull request. No action is referenced by tag.

### Phase S2: remove the ignored advisories

- [x] **S2.1 Move JWT verification to `jsonwebtoken` 12 with `aws_lc_rs` and empty both ignore lists.**
  - Scope: section 5.3. Files: `Cargo.toml`, `Cargo.lock`, `src/mcp/security/oidc.rs`, `.cargo/audit.toml`, `deny.toml`, `SECURITY.md`.
  - Acceptance: `cargo audit` and `cargo deny check` pass with `ignore = []`; `grep -c 'name = "rsa"' Cargo.lock` prints 0; OIDC tests pass unchanged.
  - Rollback: revert. The ignore entries return with it.
  - Session notes: Done. jsonwebtoken 12 with aws_lc_rs; rsa, crypto-bigint, p256, p384 and the other RustCrypto asymmetric crates left Cargo.lock. oidc.rs needed no change and the OIDC tests pass unchanged. Both ignore lists are empty. SECURITY.md had no reference to the ignored advisories, so it is unchanged.

### Phase S3: minimal CLI (before or with the 4.0.0 split pull request)

- [x] **S3.1 Add the dependency budget gate, initially report only.**
  - Scope: `scripts/check_cli_deps.py` (click, functional style) and `scripts/cli_deps_budget.yaml` holding `max_crates` and `banned_crates`. The script runs `cargo tree --locked -e normal --prefix none` for the CLI feature set and compares. Unit tests in `scripts/test_check_cli_deps.py`.
  - Acceptance: job runs and reports the current count without failing the build.
  - Session notes: Done. Script, budget file and 8 unit tests added; CI runs the tests and the report step in the security-audit job. Reports 232 unique crates and 9 banned-crate hits on macOS before S3.2.

- [x] **S3.2 Introduce the `mcp` and `xlsx` features and build each binary separately.**
  - Scope: section 5.2 in full, including every CI job listed there and `cargo auditable` builds.
  - Acceptance: both feature sets compile, pass Clippy with warnings as errors and pass tests; the release archive for each platform still contains both binaries; `cargo audit bin dist/dcert` lists no banned crate; the budget gate is switched to enforcing with `max_crates: 170`.
  - Tests: the two existing parity tests under `src/mcp/` run with `--features mcp`; a new test asserts `dcert vault list --format xlsx` gives a clear error when built without `xlsx`.
  - Rollback: revert. No published artefact changes shape, so no user facing rollback is needed.
  - Session notes: Done. `mcp` and `xlsx` features added; CLI tree is 166 crates (Linux target), budget gate enforcing at 170; clippy and tests pass for default, --features mcp and --no-default-features. `dcert kb schema` and `tls-policy schema` embed the checked-in kb schema files in the CLI (output identical to the generated schema; a test under `mcp` proves it). Builds go through scripts/ci/build_release.sh with cargo auditable (tested locally: CLI embeds 204 entries, MCP 257, chrono only in MCP). Not done: banned-crate check on the binary itself (cargo audit bin has no usable JSON listing); the source tree gate covers it. CI workflow changes are untested until a pull request runs.

- [ ] **S3.3 Publish one SBOM per binary.**
  - Scope: replace the single `dcert-sbom.cdx.json` with `dcert-cli-sbom.cdx.json` and `dcert-mcp-sbom.cdx.json`, generated per feature set. Confirm the exact flags with `cargo cyclonedx --help` (expected: `--no-default-features`, `--features`, `--describe binaries`, `--override-filename`). Attest both.
  - Acceptance: both files attached to the release and listed in `SHA256SUMS`; `SECURITY.md` updated.
  - Session notes:

### Phase S4: OpenSSL

- [ ] **S4.1 Windows OpenSSL on a supported, patched release.** Section 5.4. Stop and ask Dejan if option 3 (exception) is the only one available.
- [ ] **S4.2 OpenSSL floor gate for every artefact.** `scripts/openssl_floor.yaml` plus a CI step per build job. Includes the macOS linkage check with `otool -L`.
- [ ] **S4b (optional, later) Reduce the HTTP client.** Evaluate replacing blocking `reqwest` in `src/http.rs`, `src/trust.rs` and `src/vault.rs` with `ureq` 3 over the OpenSSL already linked. Expected saving is most of the 92 crate `reqwest` subtree. Proxy support, timeouts and the Vault client must behave identically. Do not start without Dejan's approval.

### Phase S5: Python contract (with the split pull request)

- [ ] **S5.1 Zero dependency contract tests for the `dcert` wheel.** Section 5.1. Runs against the real built wheel, not the source tree.
- [ ] **S5.2 Proxy as an optional extra.** Section 5.5. **Blocked until Dejan confirms.**
- [ ] **S5.3 Commit `uv.lock` for `dcert-mcp` and audit it.**

  ```bash
  # Step 1: create or refresh the lock file for the dcert-mcp project. Next: audit it.
  uv lock --project python/dcert-mcp

  # Step 2: audit the locked set, development tools included. Next: audit the lowest allowed versions.
  uv audit --project python/dcert-mcp --locked

  # Step 3: prove the declared floors are safe on their own. Next: wire all three into CI.
  uv pip compile python/dcert-mcp/pyproject.toml --extra proxy --extra otel \
    --resolution lowest-direct -o /tmp/lowest.txt
  uvx pip-audit -r /tmp/lowest.txt --no-deps --disable-pip --strict
  ```

### Phase S6: permanent gates

- [ ] **S6.1 Scheduled audit workflow `.github/workflows/audit.yml`.** Daily cron and manual dispatch. Runs `cargo audit`, `cargo deny check advisories`, `uv audit --locked`, the `lowest-direct` audit, `cargo audit bin` against the binaries of the latest release, and Trivy on the published image. Permissions `contents: read` and `issues: write` only. On failure it opens or updates one issue titled "Security audit failing".
- [ ] **S6.2 Workflow hardening.** Add zizmor as a required job; add `actions/dependency-review-action` on pull requests; add a second Trivy step with `ignore-unfixed: false` and `exit-code: 0` for visibility; enable secret scanning and push protection (repository setting, ask Dejan).
- [ ] **S6.3 Rules for `ci-mcp.yml` if it uses `workflow_run`.** Run only when the triggering run was a `push` to `main` of this repository and concluded successfully; never check out or execute code from the triggering ref; treat downloaded artefacts as data and verify each with `gh attestation verify` before publishing; grant `id-token: write` to the publish job alone.
- [ ] **S6.4 Dependabot.** Section 5.6.
- [ ] **S6.5 Exception expiry check.** A script fails CI when any entry in an ignore list lacks an `expires` comment or is past it.

### Phase S7: final verification

- [ ] **S7.1 After snapshot and published comparison.** Repeat S0.1 into `docs/security/after/`, add a before and after table to `SECURITY.md`, and confirm every objective in section 2.

## 7. Sequencing with the packaging split

| Order | Work | Reason |
| --- | --- | --- |
| 1 | S0, S1 | Clears the live advisory and gives a clean diff before files move. S1.1 is urgent on its own: the security audit job fails on the next push to `main`, and the release pipeline depends on it. |
| 2 | S2 | Independent of packaging. |
| 3 | S3, S4 | Must land before or with the 4.0.0 split so the first `dcert` 4.0.0 wheel already carries the minimal binary. |
| 4 | Split pull request with S5 | The wheel contract tests arrive with the wheels they test. |
| 5 | S6 | Gates need the new layout. |
| 6 | S7 | Closes the work. |

## 8. Risk register

| Risk | Likelihood | Effect | Mitigation |
| --- | --- | --- | --- |
| A build still runs plain `cargo build --release` and ships an archive without `dcert-mcp` | Medium | High | Packaging step fails when either binary is missing; wheel install test asserts both |
| CLI built with the `mcp` feature by accident | Medium | Medium | `cargo audit bin` plus the budget gate run on the packaged binary, not the source tree |
| `jsonwebtoken` 12 or `rmcp` 3.11 changes behaviour | Medium | Medium | Existing OIDC and parity tests; MCP handshake smoke test |
| Upgrades raise the MSRV above 1.91 | Medium | Low | MSRV job per feature set; raise `rust-version` deliberately if needed |
| vcpkg OpenSSL differs from the vendored build (providers, post quantum groups) | Medium | Medium | Run the post quantum tests against the Windows artefact |
| Optional proxy extra surprises users who expect the proxy by default | Medium | Low | Clear error naming the extra; migration notes; decision confirmed first |
| Security floors block resolution in a locked down mirror | Low | Medium | Floors are first patched releases, not latest |
| Scanners keep flagging the repository because of `Cargo.lock` | High | Low | Per binary SBOMs and `SECURITY.md` wording |
| A new advisory appears mid plan | High | Low | Run section 3 again at the start of every session |

## 9. Stop conditions

Stop and ask Dejan before: S5.2 (proxy extra); S4.1 if only an exception is possible; S4b; any repository setting change; any PyPI project setting; yanking a release.

## 10. Definition of done for security

- [ ] `cargo audit` and `cargo deny check` pass with empty ignore lists.
- [ ] `cargo audit bin` passes for all eight shipped binaries, and the CLI binaries contain no banned crate.
- [ ] `dcert` wheel metadata has no `Requires-Dist` line on all four platforms.
- [ ] `uv audit --locked` and the `lowest-direct` audit pass for `dcert-mcp`.
- [ ] Every artefact reports an OpenSSL version at or above the recorded floor, or a dated exception exists.
- [ ] Trivy passes on the image; the report only scan is attached to the run.
- [ ] zizmor passes on every workflow.
- [ ] The scheduled audit has run green at least once.
- [ ] Two binary SBOMs are attached to the release and attested.
- [ ] `SECURITY.md` shows the before and after table and explains the per binary evidence.

## 11. Sources

- RustSec advisory database, commit `074ea9a` of 2026-11-19: https://github.com/rustsec/advisory-db
- `RUSTSEC-2026-0462`: https://rustsec.org/advisories/RUSTSEC-2026-0462
- `RUSTSEC-2023-0071`: https://rustsec.org/advisories/RUSTSEC-2023-0071
- `RUSTSEC-2026-0387`: https://github.com/RustCrypto/crypto-bigint/pull/1365
- `jsonwebtoken` backends: https://docs.rs/crate/jsonwebtoken/latest
- OpenSSL advisory, 17 November 2026: https://www.openwall.com/lists/oss-security/2026/11/17/6
- OpenSSL advisory, 10 November 2026: https://groups.google.com/a/openssl.org/g/openssl-announce/c/RjPdEDdZiiM
- OpenSSL releases, 29 September 2026: https://groups.google.com/a/openssl.org/g/openssl-announce/c/Yl8YVPbo77s
- OpenSSL releases, 25 August 2026: https://groups.google.com/a/openssl.org/g/openssl-announce/c/MkITYirzZ2M
- Trivy action compromise, `GHSA-69fq-xp46-6x23`: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- `cargo auditable`: https://docs.rs/cargo-auditable/
- uv and Dependabot: https://docs.astral.sh/uv/guides/integration/dependabot/
- PyPI JSON API (package metadata and per release advisories): https://pypi.org/pypi/fastmcp/json
- crates.io index (versions of `openssl-src`, `openssl-sys`, `jsonwebtoken`, `rmcp`): https://index.crates.io/
