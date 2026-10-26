//! Per tool authorization.
//!
//! The global scope and role checks in [`super::oidc`] decide whether a token
//! may talk to this server at all. They do not distinguish reading a
//! certificate from revoking one. This module adds a second check, applied to
//! every `tools/call`, so a token can be admitted for analysis without also
//! being allowed to issue or revoke certificates from Vault.
//!
//! Policy comes from the environment and defaults to permissive, which keeps
//! existing deployments working:
//!
//! - `DCERT_MCP_SCOPE_<TOOL>` names the scopes or roles required for one tool,
//!   for example `DCERT_MCP_SCOPE_VAULT_REVOKE=pki.admin`.
//! - `DCERT_MCP_SCOPE_WRITE` applies to every tool that changes state.
//! - `DCERT_MCP_SCOPE_READ` applies to every read only tool.
//!
//! A tool with no applicable rule is allowed. Any listed scope or role is
//! enough (they are alternatives, not a conjunction), matching how the global
//! check treats `DCERT_MCP_REQUIRED_SCOPES`.

use super::oidc::TokenClaims;
use std::collections::BTreeMap;

/// Tools that change state on disk, in Vault or at a remote service. Anything
/// not listed here is treated as read only.
const WRITE_TOOLS: &[&str] = &[
    "convert_pfx_to_pem",
    "convert_pem_to_pfx",
    "create_keystore",
    "create_truststore",
    "create_csr",
    "export_pem",
    "vault_issue",
    "vault_sign",
    "vault_revoke",
    "vault_store",
    "vault_renew",
];

/// Resolved policy: which scopes or roles each tool requires.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolScopePolicy {
    per_tool: BTreeMap<String, Vec<String>>,
    write: Vec<String>,
    read: Vec<String>,
}

impl ToolScopePolicy {
    /// Read the policy from the environment. Called once at startup.
    pub fn from_env() -> Self {
        Self::from_vars(std::env::vars())
    }

    /// Build the policy from arbitrary variables, so it can be unit tested
    /// without mutating the process environment.
    pub fn from_vars(vars: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut policy = Self::default();
        for (key, value) in vars {
            let Some(suffix) = key.strip_prefix("DCERT_MCP_SCOPE_") else {
                continue;
            };
            let values = split_list(&value);
            if values.is_empty() {
                continue;
            }
            match suffix {
                "WRITE" => policy.write = values,
                "READ" => policy.read = values,
                tool => {
                    policy.per_tool.insert(tool.to_ascii_lowercase(), values);
                }
            }
        }
        policy
    }

    /// `true` when no rule is configured at all, so every tool is allowed.
    pub fn is_empty(&self) -> bool {
        self.per_tool.is_empty() && self.write.is_empty() && self.read.is_empty()
    }

    /// Scopes or roles required to call `tool`, most specific rule first.
    fn required_for(&self, tool: &str) -> &[String] {
        if let Some(explicit) = self.per_tool.get(tool) {
            return explicit;
        }
        if is_write_tool(tool) {
            return &self.write;
        }
        &self.read
    }

    /// Check a request against the policy. With any rule configured, a
    /// request whose tool cannot be determined is refused (fail closed).
    pub fn authorize_request(&self, request: &ToolRequest, claims: &TokenClaims) -> Result<(), String> {
        match request {
            ToolRequest::Call { tool, .. } => self.authorize(tool, claims),
            ToolRequest::NotACall => Ok(()),
            ToolRequest::Undetermined if self.is_empty() => Ok(()),
            ToolRequest::Undetermined => Err(
                "per tool authorization is configured and the tool cannot be determined \
                 (batch, non object or malformed request)"
                    .to_string(),
            ),
        }
    }

    /// Check a token against the policy for `tool`.
    pub fn authorize(&self, tool: &str, claims: &TokenClaims) -> Result<(), String> {
        let required = self.required_for(tool);
        if required.is_empty() {
            return Ok(());
        }
        let granted =
            |needle: &String| claims.scopes.iter().any(|s| s == needle) || claims.roles.iter().any(|r| r == needle);
        if required.iter().any(granted) {
            Ok(())
        } else {
            Err(format!(
                "tool '{tool}' requires one of the scopes or roles: {}",
                required.join(", ")
            ))
        }
    }
}

/// `true` when the named tool changes state.
pub fn is_write_tool(tool: &str) -> bool {
    WRITE_TOOLS.contains(&tool)
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// What a JSON-RPC request body asks for, as far as per tool authorization
/// is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRequest {
    /// A `tools/call` naming this tool.
    Call {
        /// The tool name.
        tool: String,
        /// The `target` argument (or `target_a`), redacted for logging.
        target: Option<String>,
    },
    /// Any other single method (`initialize`, `tools/list`, ...).
    NotACall,
    /// A batch, a non object body, unparsable JSON or a `tools/call` without
    /// a tool name. A per tool policy cannot be applied, so it fails closed.
    Undetermined,
}

/// Classify a request body for per tool authorization.
pub fn classify_request(body: &[u8]) -> ToolRequest {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return ToolRequest::Undetermined;
    };
    let Some(object) = value.as_object() else {
        return ToolRequest::Undetermined;
    };
    if object.get("method").and_then(serde_json::Value::as_str) != Some("tools/call") {
        return ToolRequest::NotACall;
    }
    match tool_name_from_request(&value) {
        Some(tool) => {
            let arguments = value.get("params").and_then(|p| p.get("arguments"));
            let target = ["target", "target_a"]
                .iter()
                .find_map(|k| arguments.and_then(|a| a.get(*k)).and_then(serde_json::Value::as_str))
                .map(redact_target);
            ToolRequest::Call {
                tool: tool.to_string(),
                target,
            }
        }
        None => ToolRequest::Undetermined,
    }
}

/// A probe target reduced to what an audit log may keep: scheme, host and
/// port of a URL (no credentials, path or query), the host of `host:port`,
/// and `<file>` for a local path.
pub fn redact_target(target: &str) -> String {
    const MAX: usize = 255;
    if target.contains("://") {
        return url::Url::parse(target)
            .ok()
            .and_then(|u| {
                let host = u.host_str()?.to_string();
                Some(match u.port() {
                    Some(port) => format!("{}://{host}:{port}", u.scheme()),
                    None => format!("{}://{host}", u.scheme()),
                })
            })
            .unwrap_or_else(|| "<unparsable url>".to_string());
    }
    if target.contains('/') || target.contains('\\') {
        return "<file>".to_string();
    }
    let host = target.rsplit_once('@').map_or(target, |(_, h)| h);
    host.chars().take(MAX).collect()
}

/// Extract the tool name from a JSON-RPC request body, for `tools/call` only.
/// Returns `None` for any other method, for a batch, or for a malformed body,
/// so the caller applies no per tool rule and the transport reports the error.
pub fn tool_name_from_request(body: &serde_json::Value) -> Option<&str> {
    if body.get("method")?.as_str()? != "tools/call" {
        return None;
    }
    body.get("params")?.get("name")?.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims_with(scopes: &[&str], roles: &[&str]) -> TokenClaims {
        TokenClaims {
            subject: "user".to_string(),
            issuer: "https://issuer.example".to_string(),
            audience: vec!["api".to_string()],
            expires_at: 0,
            issued_at: 0,
            authorized_party: "client".to_string(),
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            roles: roles.iter().map(|s| (*s).to_string()).collect(),
            object_id: "oid".to_string(),
            tenant_id: "tid".to_string(),
            preferred_username: "user@example".to_string(),
            token_id: "jti".to_string(),
        }
    }

    fn policy(pairs: &[(&str, &str)]) -> ToolScopePolicy {
        ToolScopePolicy::from_vars(pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())))
    }

    #[test]
    fn empty_policy_allows_everything() {
        let p = ToolScopePolicy::default();
        assert!(p.is_empty());
        assert!(p.authorize("vault_revoke", &claims_with(&[], &[])).is_ok());
    }

    #[test]
    fn per_tool_rule_takes_precedence_over_write_rule() {
        let p = policy(&[
            ("DCERT_MCP_SCOPE_WRITE", "pki.write"),
            ("DCERT_MCP_SCOPE_VAULT_REVOKE", "pki.admin"),
        ]);
        assert!(p.authorize("vault_revoke", &claims_with(&["pki.write"], &[])).is_err());
        assert!(p.authorize("vault_revoke", &claims_with(&["pki.admin"], &[])).is_ok());
        assert!(p.authorize("vault_issue", &claims_with(&["pki.write"], &[])).is_ok());
    }

    #[test]
    fn write_rule_does_not_apply_to_read_tools() {
        let p = policy(&[("DCERT_MCP_SCOPE_WRITE", "pki.write")]);
        assert!(p.authorize("analyze_certificate", &claims_with(&[], &[])).is_ok());
        assert!(p.authorize("vault_issue", &claims_with(&[], &[])).is_err());
    }

    #[test]
    fn read_rule_applies_to_read_tools() {
        let p = policy(&[("DCERT_MCP_SCOPE_READ", "cert.read")]);
        assert!(p.authorize("analyze_certificate", &claims_with(&[], &[])).is_err());
        assert!(
            p.authorize("analyze_certificate", &claims_with(&["cert.read"], &[]))
                .is_ok()
        );
    }

    #[test]
    fn a_role_satisfies_a_requirement_too() {
        let p = policy(&[("DCERT_MCP_SCOPE_WRITE", "pki.write")]);
        assert!(p.authorize("vault_issue", &claims_with(&[], &["pki.write"])).is_ok());
    }

    #[test]
    fn any_listed_value_is_enough() {
        let p = policy(&[("DCERT_MCP_SCOPE_WRITE", " pki.write , pki.admin ")]);
        assert!(p.authorize("vault_issue", &claims_with(&["pki.admin"], &[])).is_ok());
    }

    #[test]
    fn denial_message_names_the_requirement() {
        let p = policy(&[("DCERT_MCP_SCOPE_VAULT_REVOKE", "pki.admin")]);
        let err = p.authorize("vault_revoke", &claims_with(&["other"], &[])).unwrap_err();
        assert!(err.contains("vault_revoke"), "{err}");
        assert!(err.contains("pki.admin"), "{err}");
    }

    #[test]
    fn write_tools_are_classified() {
        assert!(is_write_tool("vault_revoke"));
        assert!(is_write_tool("create_keystore"));
        assert!(!is_write_tool("analyze_certificate"));
        assert!(!is_write_tool("vault_list"));
    }

    #[test]
    fn tool_name_is_read_from_a_tools_call_only() {
        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "vault_revoke", "arguments": {}}
        });
        assert_eq!(tool_name_from_request(&call), Some("vault_revoke"));

        let list = serde_json::json!({"jsonrpc": "2.0", "method": "tools/list"});
        assert_eq!(tool_name_from_request(&list), None);

        let malformed = serde_json::json!({"method": "tools/call", "params": {}});
        assert_eq!(tool_name_from_request(&malformed), None);

        let batch = serde_json::json!([{"method": "tools/call", "params": {"name": "x"}}]);
        assert_eq!(tool_name_from_request(&batch), None);
    }

    #[test]
    fn classify_request_finds_the_tool_and_redacts_the_target() {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "analyze_certificate",
                       "arguments": {"target": "https://user:pw@api.example.com:8443/x?token=abc"}}
        });
        assert_eq!(
            classify_request(body.to_string().as_bytes()),
            ToolRequest::Call {
                tool: "analyze_certificate".to_string(),
                target: Some("https://api.example.com:8443".to_string()),
            }
        );
    }

    #[test]
    fn classify_request_cannot_determine_batches_and_odd_bodies() {
        for body in [
            r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_revoke"}}]"#,
            r#""tools/call""#,
            "not json",
            r#"{"method":"tools/call","params":{}}"#,
        ] {
            assert_eq!(classify_request(body.as_bytes()), ToolRequest::Undetermined, "{body}");
        }
        assert_eq!(classify_request(br#"{"method":"tools/list"}"#), ToolRequest::NotACall);
    }

    #[test]
    fn authorize_request_fails_closed_only_when_a_policy_exists() {
        let claims = claims_with(&["pki.admin"], &[]);
        let strict = policy(&[("DCERT_MCP_SCOPE_WRITE", "pki.write")]);
        assert!(strict.authorize_request(&ToolRequest::Undetermined, &claims).is_err());
        assert!(strict.authorize_request(&ToolRequest::NotACall, &claims).is_ok());
        let open = ToolScopePolicy::default();
        assert!(open.authorize_request(&ToolRequest::Undetermined, &claims).is_ok());
    }

    #[test]
    fn redact_target_keeps_only_what_an_audit_log_may_hold() {
        assert_eq!(redact_target("https://u:p@h.example/p?q=1"), "https://h.example");
        assert_eq!(redact_target("/etc/secret.pem"), "<file>");
        assert_eq!(redact_target("certs\\a.pem"), "<file>");
        assert_eq!(redact_target("api.example.com:443"), "api.example.com:443");
        assert_eq!(redact_target("user@host.example"), "host.example");
    }
}
