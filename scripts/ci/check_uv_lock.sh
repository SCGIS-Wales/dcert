#!/usr/bin/env bash
# Fail when python/uv.lock is stale, ignoring the version of the dcert project
# itself. The release job bumps that version in pyproject.toml on every merge,
# which a plain `uv lock --check` would report as stale on every release.
set -euo pipefail

cd "$(dirname "$0")/../../python"

lock_version="$(python3 -c '
import tomllib
lock = tomllib.load(open("uv.lock", "rb"))
print(next(p["version"] for p in lock["package"] if p["name"] == "dcert"))
')"

backup="$(mktemp)"
cp pyproject.toml "$backup"
trap 'cp "$backup" pyproject.toml; rm -f "$backup"' EXIT

# Step 1: pretend the project is at the locked version. Next: check the lock.
python3 - "$lock_version" <<'PY'
import re
import sys

text = open("pyproject.toml", encoding="utf-8").read()
text = re.sub(r'(?m)^version = ".*"$', f'version = "{sys.argv[1]}"', text, count=1)
open("pyproject.toml", "w", encoding="utf-8").write(text)
PY

# Step 2: fails when a dependency or constraint changed without `uv lock`.
uv lock --check
echo "uv.lock is current (project version ignored)"
