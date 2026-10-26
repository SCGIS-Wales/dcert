use colored::*;

/// Headers whose values should be masked in debug output.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-vault-token",
    "x-auth-token",
    "api-key",
    "ocp-apim-subscription-key",
    "x-amz-security-token",
];

/// Check if a header name is sensitive and its value should be masked.
pub fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS.contains(&name.to_lowercase().as_str())
}

/// Return a sanitized header value: if the header is sensitive, mask it.
/// For Authorization/Proxy-Authorization headers with "Bearer <token>" or
/// "Basic <base64>", the auth scheme is preserved but the credential is masked.
/// For all other sensitive headers (Cookie, etc.), the entire value is masked.
pub fn sanitize_header_value(name: &str, value: &str) -> String {
    if !is_sensitive_header(name) {
        return value.to_string();
    }
    let lower_name = name.to_lowercase();
    if (lower_name == "authorization" || lower_name == "proxy-authorization")
        && let Some((scheme, _rest)) = value.trim().split_once(' ')
    {
        return format!("{scheme} ****");
    }
    "****".to_string()
}

/// Sanitize a URL by masking any password component.
pub fn sanitize_url(url_str: &str) -> String {
    match url::Url::parse(url_str) {
        Ok(mut u) => {
            if u.password().is_some() {
                let _ = u.set_password(Some("****"));
            }
            u.to_string()
        }
        // A string that does not parse may still carry `user:pass@`; mask
        // the whole userinfo rather than echo it in an error.
        Err(_) => mask_userinfo(url_str),
    }
}

/// Replace the userinfo of `scheme://userinfo@host...` with `****`, without
/// parsing the rest. Text without userinfo is returned unchanged.
fn mask_userinfo(text: &str) -> String {
    let Some(start) = text.find("://").map(|i| i + 3) else {
        return text.to_string();
    };
    let authority_end = text[start..].find(['/', '?', '#']).map_or(text.len(), |i| start + i);
    match text[start..authority_end].rfind('@') {
        Some(at) => format!("{}****{}", &text[..start], &text[start + at..]),
        None => text.to_string(),
    }
}

/// Remove PEM private key blocks from free text before it is displayed, so
/// an error message that quotes a key file (or a stream that echoed one)
/// never puts key material on a terminal or in a log. Returns a new string;
/// text without such a block is copied unchanged.
pub fn redact_key_material(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut inside = false;
    for (i, line) in text.split('\n').enumerate() {
        let trimmed = line.trim();
        let begins = trimmed.starts_with("-----BEGIN") && trimmed.contains("PRIVATE KEY");
        let ends = trimmed.starts_with("-----END") && trimmed.contains("PRIVATE KEY");
        if i > 0 && !inside {
            out.push('\n');
        }
        if begins {
            inside = true;
            out.push_str("[private key redacted]");
            continue;
        }
        if inside {
            if ends {
                inside = false;
            }
            continue;
        }
        out.push_str(line);
    }
    out
}

/// Print a debug section header to stderr.
pub fn dbg_section(enabled: bool, section: &str) {
    if enabled {
        eprintln!("{}", format!("* --- {section} ---").dimmed());
    }
}

/// Short-circuit macro that avoids format! allocation when debug is off.
#[macro_export]
macro_rules! debug_log {
    ($enabled:expr_2021, $($arg:tt)*) => {
        if $enabled {
            use colored::Colorize as _;
            eprintln!("{} {}", "*".dimmed(), format!($($arg)*));
        }
    };
}
pub use crate::debug_log;

#[cfg(test)]
mod tests {

    #[test]
    fn sanitize_url_masks_userinfo_even_when_the_url_does_not_parse() {
        assert_eq!(
            sanitize_url("http://user:hunter2@proxy.corp:3128"),
            "http://user:****@proxy.corp:3128/"
        );
        let masked = sanitize_url("http://user:hunter2@[bad");
        assert!(!masked.contains("hunter2"), "{masked}");
        assert_eq!(sanitize_url("not a url"), "not a url");
    }

    #[test]
    fn new_sensitive_headers_are_masked() {
        for name in [
            "X-Vault-Token",
            "x-auth-token",
            "api-key",
            "Ocp-Apim-Subscription-Key",
            "X-Amz-Security-Token",
        ] {
            assert!(is_sensitive_header(name), "{name}");
        }
    }
    use super::*;

    #[test]
    fn test_is_sensitive_header() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("authorization"));
        assert!(is_sensitive_header("AUTHORIZATION"));
        assert!(is_sensitive_header("Proxy-Authorization"));
        assert!(is_sensitive_header("Cookie"));
        assert!(is_sensitive_header("Set-Cookie"));
        assert!(is_sensitive_header("X-Api-Key"));
        assert!(!is_sensitive_header("Content-Type"));
        assert!(!is_sensitive_header("Host"));
        assert!(!is_sensitive_header("Accept"));
    }

    #[test]
    fn test_sanitize_header_value_bearer() {
        let result = sanitize_header_value("Authorization", "Bearer eyJhbGciOiJSUzI1...");
        assert_eq!(result, "Bearer ****");
    }

    #[test]
    fn test_sanitize_header_value_basic() {
        let result = sanitize_header_value("Authorization", "Basic dXNlcjpwYXNz");
        assert_eq!(result, "Basic ****");
    }

    #[test]
    fn test_sanitize_header_value_proxy_auth() {
        let result = sanitize_header_value("Proxy-Authorization", "Bearer token123");
        assert_eq!(result, "Bearer ****");
    }

    #[test]
    fn test_sanitize_header_value_cookie_masked_entirely() {
        let result = sanitize_header_value("Cookie", "session=abc123; other=xyz");
        assert_eq!(result, "****");
    }

    #[test]
    fn test_sanitize_header_value_opaque_auth() {
        // Auth token without a scheme prefix
        let result = sanitize_header_value("Authorization", "some-opaque-token");
        assert_eq!(result, "****");
    }

    #[test]
    fn test_sanitize_non_sensitive_header() {
        let result = sanitize_header_value("Content-Type", "application/json");
        assert_eq!(result, "application/json");
    }

    #[test]
    fn test_sanitize_url_with_password() {
        let result = sanitize_url("http://user:secret@proxy.example.com:8080");
        assert!(result.contains("****"), "password should be masked");
        assert!(!result.contains("secret"), "original password should not appear");
        assert!(result.contains("user"), "username should still appear");
    }

    #[test]
    fn test_sanitize_url_without_password() {
        let result = sanitize_url("http://proxy.example.com:8080");
        assert_eq!(result, "http://proxy.example.com:8080/");
    }

    #[test]
    fn test_sanitize_url_invalid() {
        let result = sanitize_url("not-a-url");
        assert_eq!(result, "not-a-url");
    }

    #[test]
    fn redact_key_material_strips_private_key_blocks() {
        let text = "handshake failed\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\nafter";
        let redacted = redact_key_material(text);
        assert!(!redacted.contains("MIIE"), "{redacted}");
        assert!(redacted.contains("[private key redacted]"));
        assert!(redacted.contains("after"));
        assert_eq!(redact_key_material("plain text"), "plain text");
        let cert_only = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----";
        assert_eq!(redact_key_material(cert_only), cert_only);
    }
}
