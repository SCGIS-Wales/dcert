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
pub(crate) fn file_roots() -> Vec<std::path::PathBuf> {
    if let Some(raw) = std::env::var_os("DCERT_MCP_FILE_ROOT") {
        let roots: Vec<std::path::PathBuf> = raw
            .to_string_lossy()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from)
            .collect();
        if !roots.is_empty() {
            return roots;
        }
    }
    // Two roots by default: where the server was started (the project an IDE
    // has open) and the system scratch directory. Both are places a user
    // naturally asks for certificate files. Everything else, including
    // `/etc` and `~/.ssh`, needs an explicit `DCERT_MCP_FILE_ROOT`.
    let mut roots = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }
    roots.push(std::env::temp_dir());
    roots
}

/// Canonicalise a path as far as its existing prefix allows, so a symlink in
/// the middle of the path cannot point outside an allowed root while the
/// final component does not exist yet.
fn resolve_existing_prefix(path: &std::path::Path) -> std::path::PathBuf {
    let mut probe = path.to_path_buf();
    while !probe.exists() {
        if !probe.pop() {
            break;
        }
    }
    probe.canonicalize().unwrap_or(probe)
}

/// How many links a chain may contain before it is treated as a loop.
const MAX_SYMLINK_DEPTH: usize = 16;

/// Follow a chain of symlinks at `path` and return the path a read or write
/// would actually land on, whether or not the end of the chain exists yet.
///
/// [`resolve_existing_prefix`] alone is not enough here. `Path::exists`
/// follows symlinks, so a *dangling* link is seen as absent: the probe pops to
/// the link's parent, the parent is inside a root, and the check passes while
/// the later write follows the link somewhere else entirely. A world writable
/// root such as the system temp directory makes that reachable by any local
/// user, who need only pre-plant `out.pem -> ~/.ssh/authorized_keys`.
///
/// Returns `None` for a loop or a chain deeper than [`MAX_SYMLINK_DEPTH`], so
/// the caller refuses rather than guesses.
fn resolve_link_chain(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut current = path.to_path_buf();
    for _ in 0..MAX_SYMLINK_DEPTH {
        let Ok(meta) = std::fs::symlink_metadata(&current) else {
            // Nothing at this path: the chain ends somewhere not yet created.
            return Some(current);
        };
        if !meta.file_type().is_symlink() {
            return Some(current);
        }
        let target = std::fs::read_link(&current).ok()?;
        current = if target.is_absolute() {
            target
        } else {
            current.parent()?.join(target)
        };
    }
    None
}

/// Validate a file path parameter to prevent argument injection and path
/// traversal, and confine it to the allowed roots.
///
/// Relative paths resolve against the first root; absolute paths are accepted
/// only when they lie inside one of them. A tool call therefore cannot read
/// `/etc/shadow` or write into `~/.ssh` on the host running the server.
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

    let roots: Vec<std::path::PathBuf> = file_roots()
        .into_iter()
        .map(|r| r.canonicalize().unwrap_or(r))
        .collect();
    let Some(first) = roots.first() else {
        return Err(format!(
            "{param_name} cannot be validated: no allowed root is configured"
        ));
    };

    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        first.join(p)
    };
    let Some(landed) = resolve_link_chain(&joined) else {
        return Err(format!(
            "{param_name} '{path}' resolves through a symlink loop or too many links"
        ));
    };
    let resolved = resolve_existing_prefix(&landed);
    if roots.iter().any(|root| resolved.starts_with(root)) {
        return Ok(());
    }
    Err(format!(
        "{param_name} '{path}' is outside the allowed roots ({}); set DCERT_MCP_FILE_ROOT to widen them",
        roots
            .iter()
            .map(|r| r.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
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
