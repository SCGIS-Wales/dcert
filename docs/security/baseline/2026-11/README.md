# Baseline, 2026-11-20

Raw output of the measurements in section 3 of
`docs/plans/2026-11-dcert-security-dependency-minimization.md`, taken from
`origin/main` at commit `2ab66cb` (version 3.0.80) before any change in that plan.

| File | Command |
| --- | --- |
| `cargo-audit.txt` | `cargo audit --file Cargo.lock` on a copy of the lock file outside the repository, so the ignore list does not apply |
| `cargo-tree-count.txt` | `cargo tree --locked -e normal --prefix none`, unique crates |
| `python-tree.txt` | `uv pip compile` of the three runtime requirements, Python 3.12 |
| `pip-audit.txt` | `pip-audit` on that tree |

Differences from the plan figures:

- The crate count is 261 here, not 257. This run was on macOS (aarch64), the
  plan figure is Linux x86_64; the platform specific crates differ.
- `trivy.txt` is not included. It needs a built image and Docker, and the image
  scan runs in CI on every push. Capture it in a Linux session when needed.
