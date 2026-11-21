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
  Acceptance: the JSON API shows `yanked: true`.
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

- [ ] **B.1 docs: Installation section with pip, uv and pipx** (F12, F13). Order: Homebrew, pip and uv,
  prebuilt binaries, Windows, Docker, build from source; Quick Start offers `uvx dcert example.com`.
  Session notes:
- [ ] **B.2 docs: uvx variants of the MCP client configuration** (F13).
  Session notes:
- [ ] **B.3 docs: badges and the PyPI page of dcert** (F11, F14). No Python version classifiers on dcert
  (the wheel runs no Python). Acceptance: no badge renders "missing".
  Session notes:
- [ ] **B.4 docs: dcert-mcp development instructions and environment table** (F15).
  Session notes:
- [ ] **B.5 docs: root Development, Acknowledgements and CLAUDE.md** (F16, F20).
  Session notes:
- [ ] **B.6 docs: trusted publishers in SECURITY.md and the split plan correction** (F4, F5).
  Session notes:

## Phase C: documentation gates in CI

- [ ] **C.1 ci: `scripts/check_docs_commands.py`** (F28). Walks `--help` of dcert and dcert-mcp; checks
  commands and flags in fenced blocks and inline code of the READMEs, SECURITY.md and the release
  notes template; checks the MCP tool table against tools/list. Fixture test for the F6 regression.
  Session notes:
- [ ] **C.2 ci: environment table check** (F15). Subcommand `env-table` compares the README table with
  config.yaml.
  Session notes:
- [ ] **C.3 ci: link check and wheel metadata check** (F28). lychee pinned by SHA; `twine check --strict`
  on both wheel sets.
  Session notes:

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
- [ ] **D.2 ci: post publish verification job** (F2). Poll PyPI for up to 15 minutes; install both with pip
  and uv on Linux, macOS and Windows; `--version` and a tools/list handshake.
  Session notes:
- [ ] **D.3 ci: release consistency summary** (F2). `if: always()` job checks the GitHub release assets,
  both PyPI projects, GHCR, the tap formula and Chocolatey; writes a job summary table.
  Session notes:
- [ ] **D.4 ci: recovery by workflow_dispatch** (F2). Inputs tag and project; downloads wheels from the
  release, verifies SHA256SUMS, publishes with skip-existing in the same environments.
  Session notes:
- [ ] **D.5 ci: scheduled PyPI consistency in audit.yml** (F2).
  Session notes:
- [ ] **D.6 ci: audit every archive and published wheel** (F27).
  Session notes:
- [ ] **D.7 ci: environment rename.** Not chosen (D2 option a).
  Session notes: superseded by D2 (a).

## Phase E: Python package fixes

- [ ] **E.1 fix: proxy advertises the dcert-mcp identity** (F21).
  Session notes:
- [ ] **E.2 feat: generated typed wrappers for all tools** (F22). Existing signatures unchanged.
  Session notes:
- [ ] **E.3 ci: Python 3.15 in the python-mcp matrix** (F23).
  Session notes:
- [ ] **E.4 chore: remove .coverage and fix .gitignore** (F24).
  Session notes:
- [ ] **E.5 ci: uv scenarios and MCP handshake in the install test** (F25).
  Session notes:
- [ ] **E.6 build: hash pinned requirements per extra** (F26).
  Session notes:

## Phase F: CLI wording and channel consistency

- [ ] **F.1 fix: CLI description** (F17). S1.
  Session notes:
- [ ] **F.2 docs: one sentence per program in every channel** (F31).
  S1: "dcert is a command line tool that decodes, validates and converts X.509 certificates and
  diagnoses TLS endpoints."
  S2: "dcert-mcp is a Model Context Protocol server that gives AI assistants the dcert certificate and
  TLS tools."
  Session notes:

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
