# Security

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly by opening a private security advisory on GitHub. Do **not** open a public issue.

## Authentication Architecture

dcert-mcp supports OIDC/OAuth2 authentication for HTTP transport mode, following [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2024-11-05/security).

### Transport Modes

| Mode | Auth | Use Case |
|------|------|----------|
| `stdio` (default) | None required | IDE integration, local development |
| `http` | OIDC / Static token / None | Remote deployment, multi-user environments |

### Authentication Priority

When running in HTTP mode, authentication is resolved in priority order:

1. **OIDC/OAuth2** — if `DCERT_MCP_OIDC_ISSUER` is set
2. **Static bearer token** — if only `DCERT_MCP_AUTH_TOKEN` is set
3. **No auth** — if neither is configured (not recommended for production)

### OIDC/OAuth2 Token Validation

JWT tokens are validated against:
- **Signature** — verified via JWKS (JSON Web Key Sets) with automatic key rotation
- **Issuer** — must match `DCERT_MCP_OIDC_ISSUER`
- **Audience** — must match `DCERT_MCP_OIDC_AUDIENCE` (prevents token confusion)
- **Expiry** — expired tokens are rejected
- **Authorized party** — optional client ID restriction via `DCERT_MCP_ALLOWED_CLIENTS`
- **Scopes** — optional scope enforcement via `DCERT_MCP_REQUIRED_SCOPES`
- **Roles** — optional role enforcement via `DCERT_MCP_REQUIRED_ROLES`

Supported algorithms: RS256, RS384, RS512.

### On-Behalf-Of (OBO) Token Exchange

For downstream API calls requiring user context, dcert-mcp supports the OBO token exchange flow (RFC jwt-bearer grant type):

- User tokens are **never forwarded** to downstream APIs (no passthrough)
- OBO exchange acquires a new token scoped to the downstream resource
- Classified error handling with actionable guidance for each failure mode

### Session Cache

Validated tokens are cached in-memory with:
- Sliding window inactivity TTL (default: 5 minutes, configurable via `DCERT_MCP_SESSION_TTL`)
- Maximum 10,000 entries with LRU eviction
- Automatic background cleanup of expired entries
- Tokens are never used beyond their `exp` claim

### Audit Logging

All authentication events are logged as structured JSON:
- `auth_success` — successful authentication with principal, tenant, scopes
- `auth_failure` — failed attempts with reason and remote address
- `authz_denied` — authorization denials with action context
- `obo_exchange` — OBO token exchanges with latency and outcome

### Static Token Mode

For simpler deployments, a static bearer token can be used:
- Set `DCERT_MCP_AUTH_TOKEN` to a secret value
- Tokens are compared using constant-time comparison to prevent timing attacks
- This mode has lower priority than OIDC when both are configured

## Security Controls

### Input Validation
- All MCP tool parameters are validated before use
- Target strings are checked for argument injection (no `-` prefix, no null bytes)
- File paths are validated to prevent path traversal
- Subprocess arguments are constructed safely (no shell interpolation)

### Error Handling
- Sensitive information (tokens, credentials, URLs with passwords) is scrubbed from error messages
- OBO errors are classified with actionable guidance without leaking secrets
- JWKS fetch errors do not expose internal URLs

### Network Security
- JWKS and token endpoints use HTTPS
- HTTP client timeouts prevent hanging connections
- CORS is configured for cross-origin HTTP access

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
| `DCERT_MCP_OBO_TOKEN_URL` | OBO token exchange endpoint |
| `DCERT_MCP_OBO_CLIENT_ID` | OBO client application ID |
| `DCERT_MCP_OBO_CLIENT_SECRET` | OBO client secret |
