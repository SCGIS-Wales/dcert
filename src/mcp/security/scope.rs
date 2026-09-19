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
}
