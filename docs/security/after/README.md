# After, 2026-11-20

The same measurements as `docs/security/baseline/2026-11/`, taken from `main`
after phases S0 to S4 and S6 of
`docs/plans/2026-11-dcert-security-dependency-minimization.md`.

| File | Command |
| --- | --- |
| `cargo-audit.txt` | `cargo audit --file Cargo.lock` on a copy of the lock file outside the repository (no ignore list applies) |
| `cargo-tree-count.txt` | `cargo tree --locked -e normal --prefix none --target x86_64-unknown-linux-gnu`, unique crates, per feature set |
| `python-tree.txt` | `uv export --frozen --no-emit-project` of `python/uv.lock` (runtime) |
| `pip-audit.txt` | `pip-audit` on that tree |

The Python tree is still the single package, so it still has dependencies
(64 packages, up from 62 because the security floors add a few direct
requirements). The zero dependency `dcert` wheel arrives with the PyPI split.
Binary level evidence for the latest release (`cargo audit bin`): the `dcert`
CLI embeds 199 dependencies and `dcert-mcp` 251, and `chrono` is only in the MCP
server.
