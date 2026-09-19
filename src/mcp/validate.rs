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

/// Root directory tool file parameters must stay inside. Defaults to the
/// server's working directory; operators widen or move it with
/// `DCERT_MCP_FILE_ROOT`.
pub(crate) fn file_root() -> std::path::PathBuf {
    std::env::var_os("DCERT_MCP_FILE_ROOT")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Validate a file path parameter to prevent argument injection and path
/// traversal. Relative paths are resolved against [`file_root`]; absolute
/// paths are accepted only when they lie inside it, so a tool call cannot
/// read `/etc/shadow` or write into `~/.ssh` on the host running the server.
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
    let p = std::path::Path::new(path);
    if p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(format!("{param_name} must not contain '..' path traversal sequences"));
    }
    let root = file_root();
    let root_canon = root.canonicalize().unwrap_or(root.clone());
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        root_canon.join(p)
    };
    // Canonicalise as far as the existing prefix allows so a symlink inside the
    // root cannot point back outside it.
    let mut probe = joined.clone();
    while !probe.exists() {
        if !probe.pop() {
            break;
        }
    }
    let resolved_prefix = probe.canonicalize().unwrap_or(probe);
    if !resolved_prefix.starts_with(&root_canon) {
        return Err(format!(
            "{param_name} '{path}' is outside the allowed root {} (set DCERT_MCP_FILE_ROOT to widen it)",
            root_canon.display()
        ));
    }
    Ok(())
}

/// Validate a free form value that reaches the subprocess argv (Vault mount,
/// role, TTL, serial, KV path, key names, SAN entries, HTTP header values).
/// Rejects flag lookalikes, control characters and absurd lengths.
pub(crate) fn validate_arg(value: &str, param_name: &str) -> Result<(), String> {
    const MAX_LEN: usize = 1024;
    if value.trim().is_empty() {
        return Err(format!("{param_name} must not be empty"));
    }
    if value.starts_with('-') {
        return Err(format!("Invalid {param_name}: '{value}' must not start with '-'"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{param_name} must not contain control characters"));
    }
    if value.len() > MAX_LEN {
        return Err(format!(
            "{param_name} is too long ({} bytes, maximum {MAX_LEN})",
            value.len()
        ));
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

/// Validate several `(name, value)` pairs with [`validate_arg`]; `None`
/// values are skipped.
pub(crate) fn validate_args(pairs: &[(&str, Option<&str>)]) -> Result<(), String> {
    for (name, value) in pairs {
        if let Some(v) = value {
            validate_arg(v, name)?;
        }
    }
    Ok(())
}

/// Validate every entry of a list parameter (SANs, IP SANs, certificate paths).
pub(crate) fn validate_list(values: &[String], param_name: &str, max: usize) -> Result<(), String> {
    if values.len() > max {
        return Err(format!("{param_name} has {} entries, maximum is {max}", values.len()));
    }
    for v in values {
        validate_arg(v, param_name)?;
    }
    Ok(())
}
