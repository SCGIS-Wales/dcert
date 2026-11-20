# PyPI split: `dcert` and `dcert-mcp` as two packages

Companion to `docs/plans/2026-11-dcert-security-dependency-minimization.md`
(section 5.1 and 5.5). Branches `plan/split-<n>-<slug>`; every merge to `main`
is a release, so each pull request is small and the published packages work at
every step.

## Goal

Two separate PyPI projects:

| Project | Provides | Python dependencies |
| --- | --- | --- |
| `dcert` | the `dcert` CLI | none |
| `dcert-mcp` | the `dcert-mcp` MCP server (Rust binary), plus the Python proxy and typed client behind an extra | `dcert` (same version); the proxy and OpenTelemetry add the third party packages |

`pip install dcert` must install no third party package and run no Python when
the user types `dcert`. A user of the MCP server must not need the proxy.

## Install matrix

| Command | Result |
| --- | --- |
| `pip install dcert` | `dcert` CLI |
| `pip install dcert-mcp` | `dcert-mcp` server, and `dcert` through the dependency |
| `pip install "dcert-mcp[proxy]"` | plus the FastMCP proxy, typed client and proxy command |
| `pip install "dcert-mcp[proxy,otel]"` | plus OpenTelemetry export |

## Design

1. **Layout.** `python/dcert-cli/` and `python/dcert-mcp/`, each with its own
   `pyproject.toml`. The current single project under `python/` stays until the
   cut-over (phase 4) so `main` keeps publishing a working package.
2. **`dcert` wheel.** Platform wheels only, built by `scripts/build_wheels.py`
   from the release archives. The executable goes in
   `dcert-<v>.data/scripts/`, as `ruff` and `uv` do, so pip puts it in `bin/`
   and no Python runs. No Python modules, no `download.py`, no network access.
   `Requires-Dist` is empty. Metadata comes from `python/dcert-cli/pyproject.toml`,
   read by the builder, so there is one source of truth. No sdist: on a host no
   platform wheel fits, pip says "no matching distribution".
3. **`dcert-mcp` wheel.** Platform wheel with the `dcert-mcp` executable in
   `.data/scripts` and the `dcert_mcp` Python package. `Requires-Dist:
   dcert==<same version>`. Extras `proxy` and `otel` carry every third party
   package, with the security floors of the security plan section 5.5. The
   `dcert_mcp` import is cheap: modules that need FastMCP import it lazily and,
   when it is missing, fail with one line naming the extra.
4. **Python API.** The import name moves from `dcert` to `dcert_mcp` (the old
   package is the proxy and client, not the CLI). Console scripts: `dcert-mcp`
   is the Rust binary; the proxy command becomes `dcert-mcp-proxy`
   (was `dcert-python`). This is a breaking change, hence a new major version.
5. **Versions.** Both projects always carry the same version. The split ships as
   4.x: `auto-tag` adds one to the patch of the newest `v*` tag, so a `v4.0.0`
   tag is created on the cut-over commit's parent and the first split release is
   4.0.1.
6. **Publishing.** `dcert` first, then `dcert-mcp` (it depends on `dcert`),
   each with trusted publishing and attestations from the existing `pypi`
   environment. `dcert-mcp` is a new PyPI project name.

## Phases

- [x] **Phase 0: this plan.**
- [x] **Phase 1: the `dcert` wheel.** `python/dcert-cli/pyproject.toml` and README;
  `scripts/build_wheels.py` builds it from scratch (scripts entry, metadata,
  RECORD, platform tag, glibc check kept); contract tests against the built
  wheel (zero `Requires-Dist`, no `.py` files, executable bit, scripts entry
  present, tag per platform). Security plan S5.1.
- [x] **Phase 2: the `dcert-mcp` package.** Port `python/src/dcert` to
  `python/dcert-mcp/src/dcert_mcp` with its tests; lazy FastMCP import and the
  missing-extra message; extras with the security floors; builder support for
  the second wheel kind; remove `download.py`, `checksums.json` and the binary
  search (the binary is on `PATH`).
  Session notes: the directory is `python/dcert-cli/` (a `python/dcert/` folder
  shadows the `dcert` import name and zeroed coverage in the old project). The
  `dcert-mcp` wheel is named `dcert_mcp-<v>-py3-none-<platform>.whl` (PEP 427
  escaping); `dcert_mcp.__init__` resolves helpers lazily, and the
  `dcert-mcp-proxy` console script prints one line naming the extra when
  FastMCP is missing. `python/uv.lock` for `dcert-mcp` waits for phase 3
  because `dcert==<v>` is not on PyPI until the release publishes it.
- [x] **Phase 3: CI.** Build both wheel sets, install tests per platform
  (`pip install dcert`, then `dcert-mcp` with and without the extra), the
  `lowest-direct` audit and `uv.lock` for `dcert-mcp`, publish both.
- [x] **Phase 4: cut-over.** Remove the old `python/` project, create the
  `v4.0.0` tag, migration notes in the README and CHANGELOG.
  Session notes (phases 3 and 4 landed together, on the owner's instruction to
  proceed without further confirmation): CI builds both wheel sets from the
  release archives (`python-wheels-platform` artifact), installs them on four
  platforms (`scripts/ci/wheel_install_check.py`: `dcert` alone installs no
  third party package, `dcert-mcp` installs `dcert` and nothing else, the proxy
  extra comes from PyPI), then publishes `dcert` and afterwards `dcert-mcp`
  (`publish-pypi-dcert`, `publish-pypi-mcp`). No `uv.lock` for `dcert-mcp`: the
  `dcert==<v>` pin cannot resolve before the release publishes it, so CI and the
  scheduled audit resolve the extras' requirements (`scripts/ci/
  extras_requirements.py`) at the newest and the oldest versions the ranges allow
  and audit both; the `uv` Dependabot ecosystem is removed, the `pip` one points
  at `python/dcert-mcp`. The legacy universal-wheel mode of `build_wheels.py`,
  `download.py` and the old `python/` project are gone. Nothing is yanked: 3.x
  releases of the old `dcert` stay on PyPI.

## Owner actions (cannot be done from a pull request)

- Register `dcert-mcp` on PyPI with a **pending trusted publisher**:
  repository `SCGIS-Wales/dcert`, workflow `ci.yml`, environment `pypi`.
  Until then the first upload of the new name fails. (Done; first upload 4.0.3.)
- Add a trusted publisher to the existing `dcert` project for environment
  `pypi-dcert` (repository `SCGIS-Wales/dcert`, workflow `ci.yml`). With both
  projects on environment `pypi`, PyPI minted tokens valid for `dcert-mcp`
  only and refused every `dcert` upload with "OIDC scoped token is not valid
  for project". The `publish-pypi-dcert` job now uses `pypi-dcert`.
- Confirm the breaking changes in design point 4 (import name, proxy command).
- Yanking or deprecating any release of the old `dcert` is a decision for the
  maintainer.

## Stop conditions

Stop and ask before yanking or deleting a release. The cut-over and the first
publish of `dcert-mcp` were approved by the owner ("go autonomous").
