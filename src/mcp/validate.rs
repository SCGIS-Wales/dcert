//! Input validation for tool parameters: everything that reaches the dcert
//! subprocess argv or the file system passes through here first.

/// Validate a target string to prevent argument injection.
///
/// Targets starting with `-` could be misinterpreted as CLI flags by the
/// dcert subprocess. We reject them unless they look like a valid stdin
/// indicator (bare `-`) which the MCP server doesn't support.
pub(crate) fn validate_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("Target must not be empty".to_string());
    }
    if target.starts_with('-') {
        return Err(format!(
            "Invalid target '{target}': targets must not start with '-' (looks like a CLI flag)"
        ));
    }
    // Reject targets with embedded null bytes
    if target.contains('\0') {
        return Err("Target must not contain null bytes".to_string());
    }
    Ok(())
}

/// Validate a file path parameter to prevent argument injection and path traversal.
pub(crate) fn validate_path(path: &str, param_name: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{param_name} must not be empty"));
    }
    if path.starts_with('-') {
        return Err(format!("Invalid {param_name}: '{path}' must not start with '-'"));
    }
    if path.contains('\0') {
        return Err(format!("{param_name} must not contain null bytes"));
    }
    // Reject path traversal precisely. The previous implementation used
    // `path.contains("..")` which both false-negatived on URL-encoded forms
    // and false-positived on benign filenames like `my..config.pem`. Use
    // `Path::components()` to walk the resolved structural elements and
    // reject only `Component::ParentDir` (i.e. an actual `..` segment).
    if std::path::Path::new(path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("{param_name} must not contain '..' path traversal sequences"));
    }
    Ok(())
}

/// Maximum number of certificate paths in a single truststore creation request.
pub(crate) const MAX_CERT_PATHS: usize = 100;

/// Maximum password length to prevent memory-based attacks.
pub(crate) const MAX_PASSWORD_LEN: usize = 1024;

/// Validate a password parameter for reasonable length.
pub(crate) fn validate_password(password: &str) -> Result<(), String> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(format!(
            "Password too long ({} bytes, maximum is {})",
            password.len(),
            MAX_PASSWORD_LEN
        ));
    }
    if password.contains('\0') {
        return Err("Password must not contain null bytes".to_string());
    }
    Ok(())
}

/// Validate a keystore alias (alphanumeric, hyphens, underscores, dots; max 256 chars).
pub(crate) fn validate_alias(alias: &str) -> Result<(), String> {
    if alias.is_empty() {
        return Err("Alias must not be empty".to_string());
    }
    if alias.len() > 256 {
        return Err(format!("Alias too long ({} chars, maximum is 256)", alias.len()));
    }
    if !alias
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "Invalid alias '{alias}': must contain only alphanumeric characters, hyphens, underscores, or dots"
        ));
    }
    Ok(())
}

/// Validate that a key algorithm string is one of the accepted values.
pub(crate) fn validate_key_algorithm(algo: &str) -> Result<(), String> {
    match algo {
        "rsa-4096" | "rsa-2048" | "ecdsa-p256" | "ecdsa-p384" | "ed25519" => Ok(()),
        _ => Err(format!(
            "Invalid key algorithm '{algo}': must be one of \"rsa-4096\", \"rsa-2048\", \"ecdsa-p256\", \"ecdsa-p384\", \"ed25519\""
        )),
    }
}

/// Validate that a TLS version string is one of the accepted values.
pub(crate) fn validate_tls_version(version: &str) -> Result<(), String> {
    match version {
        "1.2" | "1.3" => Ok(()),
        _ => Err(format!("Invalid TLS version '{version}': must be \"1.2\" or \"1.3\"")),
    }
}
