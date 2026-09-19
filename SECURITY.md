# Security

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly by opening a private security advisory on GitHub. Do **not** open a public issue.

## Authentication Architecture

dcert-mcp supports OIDC/OAuth2 authentication for HTTP transport mode, following [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices).

### Transport Modes

| Mode | Auth | Use Case |
|------|------|----------|
| `stdio` (default) | None required | IDE integration, local development |
| `http` | OIDC / Static token / None | Remote deployment, multi-user environments |

Both transports are served by the `rmcp` SDK, so the HTTP transport exposes the same tools and schemas as stdio rather than a separate, hand-written subset.

### HTTP Transport Controls

| Control | Default | Variable |
|---------|---------|----------|
| `Host` header allowlist (DNS rebinding) | loopback names and the bind address | `DCERT_MCP_ALLOWED_HOSTS` |
| `Origin` validation | every request carrying an `Origin` is rejected | `DCERT_MCP_ALLOWED_ORIGINS` |
| Concurrent request limit | 64 | `DCERT_MCP_MAX_CONCURRENT_REQUESTS` |
| Per-request timeout | 120 seconds | `DCERT_MCP_REQUEST_TIMEOUT` |
| Request body limit | 1 MiB | `DCERT_MCP_MAX_BODY_BYTES` |

`GET /health` sits outside the authentication layer so liveness probes need no credential; every other route is behind it. CORS runs outside authentication, so a preflight is answered rather than rejected with a 401.

### Per-Tool Authorization

Passing the global scope check admits a token to the server; it does not entitle it to every tool. Requirements can be set for one tool, for every state-changing tool, or for every read-only tool:

| Variable | Applies to |
|----------|-----------|
| `DCERT_MCP_SCOPE_<TOOL>` | One named tool, e.g. `DCERT_MCP_SCOPE_VAULT_REVOKE` |
| `DCERT_MCP_SCOPE_WRITE` | Tools that change state (issue, sign, revoke, store, renew, convert, keystore, truststore, CSR, export) |
| `DCERT_MCP_SCOPE_READ` | Read-only tools |

Any listed scope or role satisfies the requirement. A denial is logged as `authz_denied` and answered with a bare `403`.

### Authentication Priority

When running in HTTP mode, authentication is resolved in priority order:

1. **OIDC/OAuth2** — if `DCERT_MCP_OIDC_ISSUER` is set
2. **Static bearer token** — if only `DCERT_MCP_AUTH_TOKEN` is set
3. **No auth** — if neither is configured (not recommended for production)

When no authentication is configured, `dcert-mcp` refuses to start on a non-loopback bind address (e.g. the default `0.0.0.0:3000`) so an unauthenticated, subprocess-spawning endpoint is never exposed to the network by accident. Bind to `127.0.0.1`, configure authentication, or set `DCERT_MCP_ALLOW_INSECURE=1` to override.

The signature algorithm allow-list accepts only RSA (RS256/384/512) and ECDSA (ES256/384); `alg=none` and HMAC algorithms are rejected to prevent algorithm-confusion attacks. The token header is checked against that list before any key is fetched for it.

### OIDC/OAuth2 Token Validation

JWT tokens are validated against:
- **Signature** — verified via JWKS (JSON Web Key Sets) with automatic key rotation
- **Issuer** — must match `DCERT_MCP_OIDC_ISSUER`
- **Audience** — must match `DCERT_MCP_OIDC_AUDIENCE` (prevents token confusion)
- **Expiry** — expired tokens are rejected
- **Not before** — tokens that are not yet valid are rejected, with a 60 second clock-skew allowance applied explicitly
- **Authorized party** — optional client ID restriction via `DCERT_MCP_ALLOWED_CLIENTS`
- **Scopes** — optional scope enforcement via `DCERT_MCP_REQUIRED_SCOPES`
- **Roles** — optional role enforcement via `DCERT_MCP_REQUIRED_ROLES`

Supported algorithms: RS256, RS384, RS512, ES256, ES384.

### Session Cache

Validated tokens are cached in-memory with:
- Sliding window inactivity TTL (default: 5 minutes, configurable via `DCERT_MCP_SESSION_TTL`)
- Maximum 10,000 entries with LRU eviction
- Automatic background cleanup of expired entries
- Tokens are never used beyond their `exp` claim

JWKS keys are cached for `DCERT_MCP_JWKS_TTL` seconds (default 3600). A token bearing an unknown key id triggers at most one JWKS refresh per minute, so unauthenticated requests cannot be amplified into a flood against the identity provider. Discovery and JWKS fetches only run on a cache miss.

### Audit Logging

All authentication events are logged as structured JSON:
- `auth_success` — successful authentication with principal, tenant, scopes
- `auth_failure` — failed attempts with reason and remote address
- `authz_denied` — authorization denials with action context

### Static Token Mode

For simpler deployments, a static bearer token can be used:
- Set `DCERT_MCP_AUTH_TOKEN` to a secret value
- Tokens are compared in constant time over fixed-width SHA-256 digests, so neither the token's length nor its content leaks through timing
- The `Bearer` prefix is accepted in any case, matching the OIDC path
- This mode has lower priority than OIDC when both are configured

### Failure Responses

Every authentication failure returns the same bare `401 Unauthorized` with a `WWW-Authenticate: Bearer` header. The reason (missing token, bad signature, wrong issuer or audience, unknown key id) is written to the audit log and never to the response body, so an unauthenticated caller learns nothing about the identity provider configuration.

### Subprocess and File Access

- The `dcert` subprocess is run with both pipes read concurrently, so output larger than the OS pipe buffer cannot deadlock the call, and output is capped while it streams
- Secrets (certificate, keystore, truststore, CSR and Vault PFX passphrases) travel to the subprocess in its environment, never in `argv`, so they do not appear in `ps` or `/proc/<pid>/cmdline`
- Every tool parameter that reaches `argv` is validated: no leading `-`, no control characters, bounded length
- File path parameters are confined to the roots in `DCERT_MCP_FILE_ROOT`, which defaults to the server's working directory and the system temp directory: the two places a user naturally asks for certificate files. Relative paths resolve inside the first root, absolute paths are accepted only within one of them, and a symlink pointing outside them is refused. Sensitive locations such as `/etc` and `~/.ssh` need an explicit opt-in
- Concurrent subprocess invocations are bounded, and a timed-out child is killed rather than orphaned

### Vault Access Policy

- `DCERT_MCP_VAULT_ADDR_ALLOWLIST` names the Vault servers a tool call may target. When unset, a request must use the server's own `VAULT_ADDR`. Only when neither is set may a request name an arbitrary address, and then only over HTTPS (or HTTP to loopback). This closes the request-forgery path where a client points the server, with the caller's credentials, at an internal host of its choosing
- `skip_verify` in a tool call is refused unless the operator sets `DCERT_MCP_VAULT_ALLOW_SKIP_VERIFY=1`: whether Vault's certificate is checked is an operator decision, not a client one
- Vault authentication goes through the same library code as the CLI, so `vault_cacert`, `VAULT_CACERT` and `VAULT_CAPATH` are honoured on the login request, not only on the session that follows

## Security Controls

### Input Validation
- All MCP tool parameters are validated before use
- Target strings are checked for argument injection (no `-` prefix, no null bytes)
- File paths are validated to prevent path traversal
- Subprocess arguments are constructed safely (no shell interpolation)

### Error Handling
- Sensitive information (tokens, credentials, URLs with passwords) is scrubbed from error messages
- JWKS fetch errors do not expose internal URLs

### Network Security
- JWKS and token endpoints use HTTPS
- HTTP client timeouts prevent hanging connections
- CORS denies cross-origin browser access by default; set `DCERT_MCP_ALLOWED_ORIGINS`
  (comma-separated) to permit specific origins. A literal `*` allows any origin and
  is never combined with credentials — avoid it for internet-facing deployments.
- In-memory secret hygiene: Vault tokens, the issued private key, and auth secrets
  (LDAP password, AppRole secret_id) are zeroized on drop via the `zeroize` crate.
- Proxy credentials stay off the command line: the MCP `proxy`/`noproxy` tool
  parameters are passed to the `dcert` subprocess as `DCERT_PROXY`/`DCERT_NOPROXY`
  environment variables, so a proxy URL containing a password is not visible in
  the process list. Proxy URLs are masked in all diagnostic output.
- The connection-override parameters (`connect_to`, `resolve`) change only which
  address is dialled. The hostname in `target` still drives SNI and certificate
  validation, so redirecting a connection cannot silently weaken verification.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DCERT_MCP_OIDC_ISSUER` | OIDC issuer URL (enables OIDC mode) |
| `DCERT_MCP_OIDC_AUDIENCE` | Expected audience claim |
| `DCERT_MCP_OIDC_JWKS_URL` | JWKS URL (auto-discovered if omitted) |
| `DCERT_MCP_REQUIRED_SCOPES` | Comma-separated required OAuth2 scopes |
| `DCERT_MCP_REQUIRED_ROLES` | Comma-separated required app roles |
| `DCERT_MCP_ALLOWED_CLIENTS` | Comma-separated allowed client app IDs |
| `DCERT_MCP_SESSION_TTL` | Session cache inactivity TTL in seconds (default: 300) |
| `DCERT_MCP_AUTH_TOKEN` | Static bearer token (lower priority than OIDC) |
| `DCERT_MCP_ALLOWED_ORIGINS` | Comma-separated CORS allowlist for HTTP mode (default: none; `*` = any origin) |
| `DCERT_PROXY` | Forward proxy URL for the `dcert` binary; overrides `HTTPS_PROXY`/`HTTP_PROXY` |
| `DCERT_NOPROXY` | Proxy bypass list for the `dcert` binary; overrides `NO_PROXY` |
