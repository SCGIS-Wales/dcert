# Post split consistency plan for dcert 4.0.x

Author: Dejan Gregor. Date: 2026-11-21. Baseline: main at 4367b6e ("chore: bump version to 4.0.7 [skip ci]").

## Summary

The split into `dcert` and `dcert-mcp` works for users today: both 4.0.7 wheels install with pip, uv
and uvx, the CLI wheel has no dependencies, and the MCP server finds its sibling CLI. What is not yet
sound is release integrity and documentation. PyPI is missing nine `dcert` versions that have git tags
and GitHub releases, two `dcert-mcp` releases (4.0.3 and 4.0.4) cannot be installed, and no CI job
notices when a channel is skipped. The pull requests behind the split confirm the cause for 4.0.x: PyPI
refused every `dcert` upload with "OIDC scoped token is not valid for project dcert" until PR #141 gave
`dcert` its own environment, while the cause for 3.0.85, 3.0.90, 3.0.94 and 3.0.95 is still unknown and
must be read from the Actions logs. The README contains one command that fails (`--key` in place of
`--client-key`), says nothing about uv, describes Homebrew wrongly, and the release notes template prints
Docker image names in upper case, which Docker rejects.

This plan fixes the user facing errors first, then adds the gates that stop documentation and release
channels drifting again, then completes the Python package work and reconciles the October plan. Every
merge to main is a release, so each checkbox is one small, shippable pull request, and the release
cadence decision (D1) comes before the documentation phase.

## Findings

Severity: High (users fail or releases are broken), Medium (misleading or a missing control), Low
(cosmetic or housekeeping). "Owner" means it cannot be done from a pull request.

| Id | Severity | Area | Evidence | Fix | Phase |
|---|---|---|---|---|---|
| F1 | High, owner | PyPI | dcert-mcp 4.0.3 and 4.0.4 require dcert==4.0.3 and dcert==4.0.4, which do not exist | Yank both with a reason (PEP 592) | A.0 |
| F2 | High | Release | Tags without PyPI dcert: 3.0.85, 3.0.90, 3.0.94, 3.0.95, 4.0.0 to 4.0.4 (OIDC refusals, PRs #138, #139, #141) | Post publish verification, consistency summary, scheduled check, recovery dispatch | D.2 to D.5 |
| F3 | Owner decision | Release cadence | Documentation only PRs (#128, #133, #135, #142) each produced a release; 27 releases in two days | Path filter on auto tag | D.1 |
| F4 | Medium | Environments | `pypi` publishes dcert-mcp, `pypi-dcert` publishes dcert; SECURITY.md silent | Document; optional rename; protection rules | B.6, D.7 |
| F5 | Medium | Plans | Split plan design point 6 says both projects publish from the existing `pypi` environment | Correct and record the decision | B.6 |
| F6 | High | README | `dcert diagnose ... --key client.key` exits 2 | Use `--client-key` | A.1 |
| F7 | Medium | README, release notes | "On Linux it builds from source"; the formula installs prebuilt archives | Correct wording | A.1 |
| F8 | Low | README, release notes | Ubuntu 22.04 (glibc 2.35) versus glibc 2.34 | One statement: glibc 2.34 (RHEL 9, Ubuntu 22.04, Debian 12) | A.1 |
| F9 | Low | README | Startup diagnostics shows v3.0.12, omits `destinations: unrestricted` | Refresh, no hard coded version | A.1 |
| F10 | Low | README, release notes | Two `brew tap` forms | One form: `brew install scgis-wales/tap/dcert` | A.1 |
| F11 | Medium | Badges | pyversions badge for dcert renders "missing"; no dcert-mcp badge | New badge row | B.3 |
| F12 | High | uv | No README mentions uv, uvx or pipx | Verified uv and pipx commands | B.1 |
| F13 | Medium | README structure | No pip or uv subsection; two packages not explained | Restructured Installation, uvx MCP snippets | B.1, B.2 |
| F14 | Medium | PyPI page | `cargo install dcert` fails (crate not on crates.io); page is 30 lines | `cargo install --git ... --bin dcert`; fuller page | A.1, B.3 |
| F15 | Medium | dcert-mcp README | `pip install -e` impossible; environment table incomplete | CI's real commands; table checked against config.yaml | B.4, C.2 |
| F16 | Low | README | Development lists only cargo; Acknowledgements omit ureq | Full local gate; refresh | B.5 |
| F17 | Low | CLI | `dcert --version` says "CLI and MCP server" | CLI only about text | F.1 |
| F18 | Medium | CHANGELOG | Everything under "Unreleased"; two "Security" headings | Versioned structure and a per PR rule | G.1 |
| F19 | Medium | Plans | October plan: 14 unticked items with dead paths | Carry forward or supersede per item | G.2 |
| F20 | Low | CLAUDE.md | Python gate path `python/` and `../scripts` | `python/dcert-mcp`, `../../scripts` | B.5 |
| F21 | Medium | Proxy | Proxy serverInfo.version is FastMCP's | Pass version, website_url, instructions | E.1 |
| F22 | Medium | Typed client | 17 of 30 tools wrapped | Generate from tools/list with freshness check | E.2 |
| F23 | Medium | Python versions | Classifier 3.15 not tested | Restore 3.15 to the matrix | E.3 |
| F24 | Low | Hygiene | `python/dcert-mcp/.coverage` committed; .gitignore uses old layout | Remove, fix patterns | E.4 |
| F25 | Medium | Install tests | pip only | uv scenarios and MCP handshake on four platforms | E.5 |
| F26 | Medium | Locking | No lock or pinned file for dcert-mcp extras | Hash pinned requirements per extra | E.6 |
| F27 | Medium | Audit | `cargo audit bin` on the Linux archive only | Every archive and every published wheel | D.6 |
| F28 | Medium | Docs gate | No check that docs match the CLI | `scripts/check_docs_commands.py`, link check, metadata check | C.1 to C.3 |
| F29 | Low, owner | Branches | `plan/1-8-supply-chain`, `plan/5-4-live-alb` stale | Delete after check | G.3 |
| F30 | Verify | External state | See H.1 | Verification commands | H.1 |
| F31 | Low | Channels | Chocolatey title "TLS Certificate Toolkit & MCP Server"; Docker entrypoint breaks the README CLI example | One sentence per program; `--entrypoint dcert` | F.2 |
| N1 | High | Release notes | Notes print `docker pull ghcr.io/SCGIS-Wales/dcert:<v>`, which Docker rejects | Lower case in the template | A.1 |
| N2 | Low, owner | GitHub About | Description and website mention only one project | Update description; link both | Owner |
| N3 | Medium | Chocolatey | Community feed lists 3.0.78 | Verify moderation queue; cadence (D6) | D.1, owner |
| N4 | Low | Release notes | Python section lists only local wheel installs | PyPI and uv commands first | A.1 |
| N5 | High, owner | PyPI | dcert 3.0.13 to 3.0.77 (64 releases) carry a `py3-none-any` wheel or an sdist, so on Linux aarch64, musl and Windows arm64 an unpinned `pip install dcert` installs 3.0.77, the old combined package, instead of failing | Yank 3.0.13 to 3.0.77; README tells those platforms to ask for `dcert>=4` | A.0, B.1 |

## Decisions

Recorded 2026-11-21. Dejan asked for autonomous implementation, so each decision takes the plan's
recommendation; owner-only actions stay with Dejan.

- **D1 release cadence:** (a) path filter on auto-tag for documentation-only changes, plus (b) a
  `[skip release]` marker in the squash commit title as an explicit override.
- **D2 environment names:** (a) keep `pypi` and `pypi-dcert` and document them. D.7 is not done.
- **D3 environment protection:** owner action. Recommendation: main branch and `v*` tags, no reviewers.
- **D4 crates.io:** document `cargo install --git`; do not publish.
- **D5 October plan items:** as in G.2.
- **D6 Chocolatey cadence:** push only when no earlier version is waiting for moderation.
- **D7 stale branches:** owner action after confirming no open pull request.
- **D8 typed wrappers:** generate; existing 17 signatures unchanged.

## 0. Operating instructions

Resume:

```bash
# Show the first unticked checkbox in this plan; next: read that item in full
grep -n -m1 '^- \[ \]' docs/plans/2026-11-post-split-consistency.md
# Confirm main is current and clean before branching; next: create the branch
git switch main && git pull --ff-only && git status --short
```

Rules: branch `plan/<phase>-<n>-<slug>`; one pull request per checkbox; conventional commits; author and
committer api-py; no AI or bot attribution; each pull request adds its CHANGELOG entry and ticks its own
box with Session notes. Merge with
`gh pr merge <N> --squash --delete-branch --author-email 5954680+api-py@users.noreply.github.com`.

Local gate: see CLAUDE.md.

Stop conditions (stop and ask Dejan): PyPI project settings or yanking; GitHub environment, branch
protection or repository settings; deleting remote branches; publishing to crates.io; renaming
environments; a release where any channel fails; any CI failure not explained by the change.

## Phase A: owner actions and urgent fixes

- [ ] **A.0 Owner: yank dcert-mcp 4.0.3 and 4.0.4.** https://pypi.org/manage/project/dcert-mcp/releases/,
  Options, Yank, reason "Depends on dcert==<v>, which was never published; use 4.0.5 or later".
  Acceptance: the JSON API shows `yanked: true`. Also yank dcert 3.0.13 to 3.0.77 (N5), reason
  "Superseded by dcert 4.x; on platforms without a 4.x wheel use Docker or build from source",
  so an unpinned install on an unsupported platform fails instead of installing 3.0.77.
  Session notes:
- [x] **A.1 fix: correct documented commands that fail or mislead** (F6 to F10, F14 part, N1, N4).
  README.md, python/dcert-cli/README.md, release notes template in ci.yml: `--client-key`; Homebrew
  installs prebuilt binaries (architectures read from the tap formula); glibc 2.34 (RHEL 9, Ubuntu
  22.04, Debian 12) everywhere; startup example from a real run; `brew install scgis-wales/tap/dcert`;
  `cargo install --git https://github.com/SCGIS-Wales/dcert --locked --bin dcert dcert`; lower case Docker
  lines; template Python section prints pip and uv commands before the wheel table.
  Session notes: 2026-11-21. Tap formula 4.0.7 installs prebuilt archives for macOS Intel,
  macOS arm64 and Linux x86_64. `dcert diagnose --help` lists `--client-key`; the old `--key`
  exits 2. Startup lines captured from a 4.0.7 run (`destinations: unrestricted` added, version
  shown as `<version>`). Docker CLI examples fixed with `--entrypoint dcert` (entrypoint is
  dcert-mcp). `cargo install --git ... --bin dcert dcert` installs only `dcert`.

## Phase B: README restructure and uv documentation

- [x] **B.1 docs: Installation section with pip, uv and pipx** (F12, F13). Order: Homebrew, pip and uv,
  prebuilt binaries, Windows, Docker, build from source; Quick Start offers `uvx dcert example.com`.
  Session notes: 2026-11-21, verified on macOS arm64 with uv 0.10.9, pipx 1.18.19, Python 3.12:
  `uvx dcert@4.0.7`, `uv tool install dcert`, `uv tool install dcert-mcp --with-executables-from
  dcert` (three commands), `uv pip install dcert-mcp` (two packages), `[proxy]` (proxy help runs),
  `uv add dcert-mcp` then `uv run dcert-mcp --version`, `pipx install dcert`, `pipx install
  --include-deps dcert-mcp` (three commands). Linux aarch64 checked with `uv pip install
  --python-platform aarch64-unknown-linux-gnu` (lists the four wheel platforms) and `pip download
  --platform manylinux_2_34_aarch64`: `dcert==4.0.7` has no match, but unpinned `dcert` resolves
  to 3.0.77 (finding N5). The Linux x86_64 wheel install is exercised by `wheel-install-test`.
  No Docker on this host, so the container runs were not repeated.
- [x] **B.2 docs: uvx variants of the MCP client configuration** (F13).
  Session notes: 2026-11-21. One "Without installing (uvx)" subsection after the Claude Code
  block covers the `mcpServers` clients, VS Code and `claude mcp add`; the Docker snippet is kept.
  Verified with an initialize and tools/list handshake through `uvx dcert-mcp@4.0.7` on macOS:
  serverInfo 4.0.7, 30 tools. `claude mcp add` itself was not run, to leave the user's Claude Code
  configuration untouched.
- [x] **B.3 docs: badges and the PyPI page of dcert** (F11, F14). No Python version classifiers on dcert
  (the wheel runs no Python). Acceptance: no badge renders "missing".
  Session notes: 2026-11-21. shields.io JSON: `pypi/pyversions/dcert` is "missing",
  `pypi/pyversions/dcert-mcp` is "3.12 | 3.13 | 3.14 | 3.15", both `pypi/v` badges render 4.0.7.
  uv and ruff do declare Python 3.x classifiers, but they contain Python code; the dcert wheel is
  one executable, so the pyversions badge uses dcert-mcp. Badge rows in the root README, both
  package READMEs. dcert PyPI page rewritten per R5 (examples run against a 4.0.7 build).
- [x] **B.4 docs: dcert-mcp development instructions and environment table** (F15).
  Session notes: 2026-11-21. Table rebuilt from `subprocess.passthrough_env` (29 entries in six
  groups) between `env-table` markers for C.2. Development steps run as written in a fresh uv
  venv on Python 3.12: ruff, ruff format, mypy, pytest with DCERT_MCP_BINARY (322 passed,
  99.28 % coverage).
- [x] **B.5 docs: root Development, Acknowledgements and CLAUDE.md** (F16, F20).
  Session notes: 2026-11-21. Acknowledgements from `cargo tree -e normal --depth 1` (ureq,
  rust_xlsxwriter, rustls-native-certs, serde_json added). `python -m pytest scripts -q`: 105
  passed.
- [x] **B.6 docs: trusted publishers in SECURITY.md and the split plan correction** (F4, F5).
  Session notes: 2026-11-21. SECURITY.md "Release publishing" with a job, environment and order
  table read from ci.yml; split plan design point 6 corrected with the one-workflow decision.

## Phase C: documentation gates in CI

- [x] **C.1 ci: `scripts/check_docs_commands.py`** (F28). Walks `--help` of dcert and dcert-mcp; checks
  commands and flags in fenced blocks and inline code of the READMEs, SECURITY.md and the release
  notes template; checks the MCP tool table against tools/list. Fixture test for the F6 regression.
  Session notes: 2026-11-21. Arguments are read left to right like clap, so parent flags before
  a subcommand (`dcert vault --debug issue`) and the default `check` subcommand work; flags that
  take values are read from help. On this branch: 451 flags, 30 tools, no problems; reverting
  the A.1 fix (`--key`) makes it fail on README lines 475, 484 and 1086. Every flag of both
  binaries is already mentioned somewhere, so `undocumented_ok` starts empty. `dcert-mcp-proxy`
  is not walked: the job has no FastMCP install, and its flags are Python (click) not clap.
- [x] **C.2 ci: environment table check** (F15). Subcommand `env-table` compares the README table with
  config.yaml.
  Session notes: 2026-11-21. Reads the names between the `env-table` markers added in B.4 and
  compares them with `subprocess.passthrough_env` (29 entries) in both directions, plus
  duplicates. Tests: fixture drift both ways, and the repository table is current.
- [x] **C.3 ci: link check and wheel metadata check** (F28). lychee pinned by SHA; `twine check --strict`
  on both wheel sets.
  Session notes: 2026-11-21. lychee-action v2.9.0 (e7477775) with `--include-fragments` over the
  root, docs, python and kb Markdown; placeholders, private hosts, login pages and not yet
  published release assets in `.lycheeignore`. `twine check --strict` runs in
  `build-platform-wheels` before upload; the published 4.0.7 wheels pass it and both new package
  READMEs render with readme_renderer.
  The first CI run found 10 real broken anchors: the README table of contents linked
  `#dcert-check--certificate-analysis-default`, but GitHub maps each space and hyphen of
  "dcert [check] -- ..." to its own `-` (`#dcert-check----...`); fixed in this PR.

## Phase D: release integrity

- [x] **D.1 ci: release cadence as decided in D1** (F3, N3). Auto-tag exits early when every changed path
  matches `scripts/release_paths.yaml` or the commit title has `[skip release]`; Chocolatey push gated
  per D6.
  Session notes: 2026-11-21. `scripts/ci/release_paths.py` with `scripts/release_paths.yaml`;
  auto-tag creates no tag when every changed path matches or the title has `[skip release]`.
  Package READMEs are not listed (they are the PyPI long descriptions). Dry run: the PR #142
  push (c0ec73c..a6eb602) gives `release=false`; the 4.0.7 push gives `release=true`. The D6
  Chocolatey gate is not done: Dejan excluded Chocolatey work, and versions waiting for
  moderation are not visible in the public feed, so the gate stays an owner check.
  Follow-up the same day: main runs share one concurrency group, and a newer push cancels a
  pending run, so comparing with `github.event.before` could drop a code change whose run was
  cancelled. auto-tag now passes the newest `v*` tag as `--before`; an empty diff since the tag
  means no release.
  Also: when main moves during a release run, the bump push is rejected; auto-tag now ends with
  `created=false` and a notice instead of failing, and the newer run releases both changes.
- [x] **D.2 ci: post publish verification job** (F2). Poll PyPI for up to 15 minutes; install both with pip
  and uv on Linux, macOS and Windows; `--version` and a tools/list handshake.
  Session notes: 2026-11-21. `scripts/ci/release_check.py` (click, functions) with `wait-pypi`
  and `handshake`; job `verify-pypi` (matrix ubuntu, macos, windows; bash on all three; uv
  0.13.9 from pip as elsewhere in the workflows). The handshake compares tools/list with the
  README tool table rather than a fixed 30, so adding a tool needs only the README row C.1
  already enforces. Checked locally: `wait-pypi --version 4.0.8` passes at once;
  `handshake` against the installed 4.0.7 server reports 30 tools.
- [x] **D.3 ci: release consistency summary** (F2). `if: always()` job checks the GitHub release assets,
  both PyPI projects, GHCR, the tap formula and Chocolatey; writes a job summary table.
  Session notes: 2026-11-21. `release_check.py consistency`; GHCR is checked through the
  registry API with an anonymous pull token (no Docker needed), the tap through the contents
  API. Chocolatey is reported but not required: the job is skipped without a key and the feed
  shows a version only after moderation. Run locally: 4.0.8 all ok; 4.0.4 reports the missing
  PyPI dcert (the F2 gap); 4.0.9 during its own release run reports the release and PyPI as
  missing and GHCR and the tap as ok.
- [x] **D.4 ci: recovery by workflow_dispatch** (F2). Inputs tag and project; downloads wheels from the
  release, verifies SHA256SUMS, publishes with skip-existing in the same environments.
  Session notes: 2026-11-21. Jobs `recover-guard`, `recover-pypi-dcert` (environment
  `pypi-dcert`), `recover-pypi-mcp` (environment `pypi`, after dcert). The guard validates the
  tag format, that the tag exists, downloads the wheels and `SHA256SUMS` from the release,
  runs `sha256sum -c --strict` and requires the four wheels of each selected project to be
  present and listed; dry run of the same checks on v4.0.8 passed. Dispatch runs use their own
  concurrency group so they cannot cancel a pending release run. Not run for 3.0.95 or 4.0.4:
  filling old versions is Dejan's decision (stop condition); note that 3.0.x wheels are the
  old combined package.
- [x] **D.5 ci: scheduled PyPI consistency in audit.yml** (F2).
  Session notes: 2026-11-21. Job `pypi-parity` in audit.yml, in the report job's needs.
  `release_check.py pypi-parity` checks that the newest release older than `--grace-minutes`
  (90) is present and not yanked on both projects; comparing "newest tag equals newest PyPI
  version" gave a false failure while a release was in flight (the GitHub release appears
  before the PyPI upload), so the check is presence of the settled release. Live: 4.0.7
  (90 min grace) and 4.0.8 (no grace) pass; 4.0.4 would fail for dcert (unit test).
- [x] **D.6 ci: audit every archive and published wheel** (F27).
  Session notes: 2026-11-21. `cargo audit bin` finds cargo auditable data in all eight
  executables of a release (ELF, Mach-O x86_64 and arm64, PE) and of the wheels. Both new steps
  run locally against v4.0.9 archives and the 4.0.8 PyPI wheels: no vulnerability, one allowed
  informational warning (chrono RUSTSEC-2026-0543, dcert-mcp only), and the dcert METADATA has
  no `Requires-Dist`.
- [ ] **D.7 ci: environment rename.** Not chosen (D2 option a).
  Session notes: superseded by D2 (a).

## Phase E: Python package fixes

- [x] **E.1 fix: proxy advertises the dcert-mcp identity** (F21).
  Session notes: 2026-11-21. FastMCP 4.2.4 `FastMCP.__init__` accepts `version` and
  `website_url`, which `create_proxy(**settings)` passes on. Before: `serverInfo` was
  `{name: dcert-mcp, version: 4.2.4}`. `create_server` now passes `dcert_mcp.__version__` and the
  repository URL. Instructions need no code: a raw stdio handshake shows FastMCP already
  forwards the Rust server's `instructions` in `initialize` (`FastMCP.instructions` stays
  `None`, which misled the first check). Unit test on the server object; integration test
  through `fastmcp.Client` checks name, version, website and that the instructions mention
  `analyze_certificate`.
- [x] **E.2 feat: generated typed wrappers for all tools** (F22). Existing signatures unchanged.
  Session notes: 2026-11-21. D8 (generate) taken. `scripts/gen_typed_tools.py` reads tools/list,
  skips every tool `tools.py` already wraps, and writes `generated_tools.py` (13 wrappers,
  keyword-only, typed from the JSON schema incl. `$defs` and nullable types; a schema parameter
  named `timeout` becomes `timeout_`). The output is already ruff-formatted and passes
  `mypy --strict`. Exported lazily from `dcert_mcp`; additive only, no existing signature
  changed. `--check` runs in the `docs-commands` job. Tests: argument building, required
  arguments, every wrapper calls its own tool, and (integration) every server tool has a
  wrapper. 331 passed, 99.32 %.
- [x] **E.3 ci: Python 3.15 in the python-mcp matrix** (F23).
  Session notes: 2026-11-21. Locally on CPython 3.15.2 with the proxy, otel and dev extras:
  mypy clean, 326 passed (99.29 %), integration included. "3.15" added to the matrix; the
  classifier stays.
- [x] **E.4 chore: remove .coverage and fix .gitignore** (F24).
  Session notes: 2026-11-21. `git rm --cached python/dcert-mcp/.coverage`; `.gitignore` patterns
  moved to `python/*/`, with `.coverage`, `coverage.xml`, `extras.txt`, `runtime.in`,
  `latest.txt` and `lowest.txt`. `git ls-files` finds none of them.
- [x] **E.5 ci: uv scenarios and MCP handshake in the install test** (F25).
  Session notes: 2026-11-21. `wheel_install_check.py` gains `check_uv` (uv pip into a fresh
  venv, exactly two packages; `uv tool install --with-executables-from dcert` links exactly
  `dcert`, `dcert-mcp`, `dcert-mcp-proxy`; `uv tool run --from dcert==<v>`, which is `uvx`) and
  `handshake` against the Rust server (scenario 2) and the proxy (scenario 3), compared with the
  README tool table instead of a separate `mcp_tools.yaml`. uv 0.13.9 is installed from pip as in
  the other jobs rather than adding setup-uv. The `Env` class stays (replacing it would not be a
  small diff). Scenario 3 now installs the local wheels before the extra: with version 4.0.8
  already on PyPI, pip had taken the published wheel and the proxy handshake caught it
  (FastMCP's 4.2.4 reported). Run locally on macOS arm64 against wheels built from this tree:
  all scenarios pass, both handshakes report dcert-mcp 4.0.8 with 30 tools.
- [ ] **E.6 build: hash pinned requirements per extra** (F26).
  Session notes:

## Phase F: CLI wording and channel consistency

- [x] **F.1 fix: CLI description** (F17). S1.
  Session notes: 2026-11-21. `DCERT_DESCRIPTION` and `long_about` in src/cli.rs and the Cargo
  `description` set to S1; a unit test asserts the constant equals `CARGO_PKG_DESCRIPTION` and
  does not mention MCP. `tests/cli_tests.rs::test_no_args_shows_help` matched the old
  wording and now matches S1.
- [x] **F.2 docs: one sentence per program in every channel** (F31).
  S1: "dcert is a command line tool that decodes, validates and converts X.509 certificates and
  diagnoses TLS endpoints."
  S2: "dcert-mcp is a Model Context Protocol server that gives AI assistants the dcert certificate and
  TLS tools."
  Session notes: 2026-11-21. S2 in `MCP_DESCRIPTION` (help, version, serverInfo; the existing
  serverInfo test reads the constant), S1 and S2 as the PyPI summaries and in the README header,
  Homebrew desc "Decode, validate and convert X.509 certificates and diagnose TLS endpoints"
  (74 characters, no article, does not start with the name, as `brew audit` wants), OCI title
  and description labels through docker/metadata-action. Not done: the Chocolatey nuspec (Dejan
  excluded Chocolatey work) and the Glama listing (external, owner). Docker examples already use
  `--entrypoint dcert` since A.1.

## Phase G: changelog and plan reconciliation

- [ ] **G.1 docs: CHANGELOG structure** (F18). Keep a Changelog layout; each PR adds one line under
  Unreleased; the release job moves Unreleased under the new version heading.
  Session notes:
- [ ] **G.2 docs: reconcile the October plan** (F19). Carry forward 5.4, 6.1 to 6.5, 7.1, 7.2, 8.1;
  supersede 7.3 (E.2), 7.4 (B.2), 7.5 (C.1, E.2), 8.2 (B, F), 8.3 (A.1, G.1).
  Session notes:
- [ ] **G.3 Owner: stale branches** (F29).
  Session notes:

## Phase H: final verification

- [ ] **H.1 Verification against the resulting release.** Tags versus PyPI for both projects; install from
  PyPI; handshake; GHCR tags; Chocolatey feed; release assets; open issues and pull requests.
  Session notes:

## Owner actions

Yank dcert-mcp 4.0.3 and 4.0.4 (A.0); set environment protection on `pypi` and `pypi-dcert` (D3);
update the GitHub repository description and website (N2); check the Chocolatey moderation queue and
the Glama listing; delete stale branches if agreed (G.3).

## Definition of done

Every checkbox ticked or marked superseded with a reason; both broken dcert-mcp releases yanked; no new
tag lacks a PyPI release of either project, enforced by D.2, D.3 and D.5; README commands, flags, tools
and environment tables checked by CI; uv, uvx and pipx documented and tested; proxy reports the
dcert-mcp version; CHANGELOG versioned; October plan reconciled; the H.1 checks pass against the release
that contains the last pull request of this plan.
