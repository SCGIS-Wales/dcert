#!/usr/bin/env bash
# Run inside debian:trixie (OpenSSL 3.5) with the ubuntu 22.04 built dcert
# mounted at /usr/local/bin/dcert. Starts a loopback TLS 1.3 server that only
# accepts X25519MLKEM768 and asserts dcert names the negotiated group and
# reports the post quantum probe as supported.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends openssl jq ca-certificates >/dev/null

openssl version
dcert --version

work="$(mktemp -d)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=test-server" -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null

# Two connections: the main handshake and the --pq-probe handshake.
openssl s_server -accept 4443 -key "$work/key.pem" -cert "$work/cert.pem" \
  -tls1_3 -groups X25519MLKEM768 -www -quiet &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  if (exec 3<>/dev/tcp/127.0.0.1/4443) 2>/dev/null; then break; fi
  sleep 0.1
done

dcert https://127.0.0.1:4443 --no-verify --pq-probe --format json >"$work/out.json" || true
jq '.connection | {tls_version, tls_key_exchange_group, key_exchange_class, post_quantum_probe}' "$work/out.json"

group="$(jq -r '.connection.tls_key_exchange_group // empty' "$work/out.json")"
probe="$(jq -r '.connection.post_quantum_probe.status // empty' "$work/out.json")"
if [[ "$group" != "X25519MLKEM768" ]]; then
  echo "::error::negotiated group not named (got '${group:-none}'), expected X25519MLKEM768"
  exit 1
fi
if [[ "$probe" != "supported" ]]; then
  echo "::error::post quantum probe reported '${probe:-none}', expected supported"
  exit 1
fi
echo "negotiated group named: $group; probe: $probe"
