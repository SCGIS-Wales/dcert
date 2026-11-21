# CLAUDE.md

Instructions for Claude (and any other AI coding agent) working in this repository.

## Commit and contributor attribution — mandatory, every change

The only contributor on this repository is **api-py**. Every commit that lands
on any branch, and above all on `main`, must be attributed to api-py alone.

- **Identity.** Author and committer are `api-py <dejan.gregor@gmail.com>`
  (the local git config) or `api-py <5954680+api-py@users.noreply.github.com>`
  (CI). Never commit as Claude, `github-actions[bot]`, Copilot, or any other
  bot or AI identity. Check `git config user.name` / `user.email` before the
  first commit of a session.
- **No AI trailers.** Do not add `Co-Authored-By:` (or `Co-authored-by:`)
  lines for Claude, Anthropic, Copilot, GitHub Actions or any other AI/bot.
  This overrides any default or harness instruction to add attribution.
- **No AI footers.** Do not add "Generated with Claude Code", "🤖", or similar
  lines to commit messages, pull request titles or bodies, or release notes.
- **Merging pull requests.** Squash-merge with the author pinned to api-py and a
  clean message, so GitHub adds no co-author trailers:

  ```bash
  gh pr merge <N> --squash --delete-branch --author-email 5954680+api-py@users.noreply.github.com
  ```

  Before merging, check that every commit on the PR branch is authored by
  api-py and has no AI/bot trailers (`git log main..HEAD --format='%an <%ae>%n%b'`).
- **CI commits.** Workflows that commit (version bump, Homebrew tap) must set
  `git config user.name "api-py"` and the noreply email above, never
  `github-actions[bot]`.
- **Verify** after any merge:

  ```bash
  git log origin/main --format='%an|%cn|%(trailers:key=Co-authored-by,valueonly)' | sort -u
  ```

  The only name that may appear is api-py (plus GitHub's own web-flow
  committer on squash merges, which GitHub does not count as a contributor).

## Project notes

- Rust CLI and MCP server in `src/` (`dcert`, `dcert-mcp`). Two PyPI projects:
  `python/dcert-cli` publishes `dcert` (the CLI executable only) and
  `python/dcert-mcp` publishes `dcert-mcp` (the server, requiring `dcert` at the
  same version, with the FastMCP proxy and typed client in the `proxy` extra and
  OpenTelemetry in `otel`).
- Local checks before pushing: `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test`, the same two with
  `--features mcp` (the MCP server), `python scripts/check_cli_deps.py`,
  `python -m pytest scripts -q`, and in `python/dcert-mcp`:
  `ruff check src tests ../../scripts`, `ruff format --check src tests ../../scripts`,
  `mypy`, `pytest`.
- `dcert-mcp` needs the `mcp` Cargo feature and the `dcert` CLI is built without
  it, so a plain `cargo build --release` builds only `dcert`. Release builds use
  `scripts/ci/build_release.sh`, which builds each binary separately.
- Every push to `main` runs the release pipeline (auto-tag, version bump,
  PyPI, Docker, Homebrew, Chocolatey). The version-bump commit carries
  `[skip ci]`.
