#!/usr/bin/env bash
# Install a pinned Terraform release on a CI runner after checking it against
# the release's SHA256SUMS. Usage: install_terraform.sh <version>
set -euo pipefail

version="${1:?usage: install_terraform.sh <version>}"
dest="${RUNNER_TEMP:-/tmp}/terraform-bin"
base="https://releases.hashicorp.com/terraform/${version}"
archive="terraform_${version}_linux_amd64.zip"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
curl -sSfO "${base}/${archive}"
curl -sSfO "${base}/terraform_${version}_SHA256SUMS"
grep " ${archive}\$" "terraform_${version}_SHA256SUMS" | sha256sum -c -
mkdir -p "$dest"
unzip -q -o "$archive" -d "$dest"
echo "$dest" >> "${GITHUB_PATH:-/dev/null}"
"$dest/terraform" version
