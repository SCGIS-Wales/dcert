#!/usr/bin/env bash
# Build the two release binaries separately, each with its own embedded
# dependency list (cargo auditable), and copy each aside straight after its own
# build.
#
# Why two builds: dcert-mcp needs the `mcp` Cargo feature, and the dcert CLI
# must be built without it so its dependency tree, and the list embedded in the
# binary, never contains the MCP stack. A plain `cargo build --release` builds
# only dcert (dcert-mcp has required-features = ["mcp"]) and would silently
# ship an archive without dcert-mcp.
#
# Environment:
#   TARGET  optional Rust target triple, as for `cargo build --target`
#   OUT     output directory for the two binaries (default: dist-bin)
set -euo pipefail

out="${OUT:-dist-bin}"
target_args=()
release_dir="target/release"
if [ -n "${TARGET:-}" ]; then
  target_args=(--target "$TARGET")
  release_dir="target/${TARGET}/release"
fi
exe=""
case "${TARGET:-$(uname -s)}" in *windows* | MINGW* | MSYS*) exe=".exe" ;; esac

rm -rf "$out"
mkdir -p "$out"

# No --locked: the release job stamps the new version into Cargo.toml first,
# which updates the package entry in Cargo.lock.
# Step 1: the CLI, default features, no mcp. Next: copy it aside.
cargo auditable build --release ${target_args[@]+"${target_args[@]}"} --bin dcert
cp "${release_dir}/dcert${exe}" "${out}/dcert${exe}"

# Step 2: the MCP server with the mcp feature. Next: copy it aside and verify both exist.
cargo auditable build --release ${target_args[@]+"${target_args[@]}"} --bin dcert-mcp --features mcp
cp "${release_dir}/dcert-mcp${exe}" "${out}/dcert-mcp${exe}"

for binary in "dcert${exe}" "dcert-mcp${exe}"; do
  if [ ! -s "${out}/${binary}" ]; then
    echo "error: ${out}/${binary} is missing or empty" >&2
    exit 1
  fi
done
ls -l "$out"
