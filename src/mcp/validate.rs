//! Input validation for tool parameters: everything that reaches the dcert
//! subprocess argv or the file system passes through here first.
//!
//! The checks here are synchronous and run inside async tool handlers. That
//! is a deliberate choice: the only file system work is [`validate_path`],
//! which performs a bounded handful of `lstat`/`readlink`/`realpath` calls
//! (at most [`MAX_SYMLINK_DEPTH`] links plus the path's depth) on local
//! paths. Moving each of them to `spawn_blocking` would cost a thread
//! hand-off per parameter for microseconds of work and would force the
//! parameter structs' `validate` methods to become async as well. Should a
//! deployment ever validate paths on a slow network file system, wrapping the
//! call sites is the place to revisit.

/// Reject a value that the dcert subprocess would parse as a flag or that
/// cannot be passed as an argument at all.
///
/// Every argv bound parameter shares these three rules: it must not be empty
/// (whitespace only counts as empty), must not start with `-` and must not
/// contain a NUL byte. The specific validators layer their own rules on top.
pub(crate) fn reject_flag_like(value: &str, param_name: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{param_name} must not be empty"));
    }
    if value.starts_with('-') {
        return Err(format!(
            "Invalid {param_name}: '{value}' must not start with '-' (looks like a CLI flag)"
        ));
    }
    if value.contains('\0') {
        return Err(format!("{param_name} must not contain null bytes"));
    }
    Ok(())
}

/// Validate a target string to prevent argument injection.
///
/// Targets starting with `-` could be misinterpreted as CLI flags by the
/// dcert subprocess. We reject them unless they look like a valid stdin
/// indicator (bare `-`) which the MCP server doesn't support.
pub(crate) fn validate_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("Target must not be empty".to_string());
    }
    reject_flag_like(target, "target")
}

/// Roots tool file parameters must stay inside. Defaults to the server's
/// working directory only; operators widen or move it with
/// `DCERT_MCP_FILE_ROOT` (comma separated). The first root is also the
/// working directory of every dcert child process.
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
    // The system temp directory is deliberately not a default root: it is
    // world writable, so any local user could plant files or links there.
    std::env::current_dir().into_iter().collect()
}

/// The first allowed root, canonicalised: the directory relative paths
/// resolve against and the working directory of the dcert child.
pub(crate) fn primary_root() -> Option<std::path::PathBuf> {
    file_roots().into_iter().next().map(|r| r.canonicalize().unwrap_or(r))
}

/// Canonicalise a path as far as its existing prefix allows and re-append
/// the components that do not exist yet, so a symlink in the middle of the
/// path cannot point outside an allowed root while the final component does
/// not exist yet.
fn canonicalise_with_tail(path: &std::path::Path) -> std::path::PathBuf {
    let mut probe = path.to_path_buf();
    let mut tail = Vec::new();
    while !probe.exists() {
        match probe.file_name() {
            Some(name) => tail.push(name.to_os_string()),
            None => break,
        }
        if !probe.pop() {
            break;
        }
    }
    let mut resolved = probe.canonicalize().unwrap_or(probe);
    for name in tail.iter().rev() {
        resolved.push(name);
    }
    resolved
}

/// How many links a chain may contain before it is treated as a loop.
const MAX_SYMLINK_DEPTH: usize = 16;

/// Follow a chain of symlinks at `path` and return the path a read or write
/// would actually land on, whether or not the end of the chain exists yet.
///
/// [`canonicalise_with_tail`] alone is not enough here. `Path::exists`
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
/// traversal, confine it to the allowed roots and return the canonical
/// absolute path the dcert child must be given.
///
/// Relative paths resolve against the first root; absolute paths are accepted
/// only when they lie inside one of them. A tool call therefore cannot read
/// `/etc/shadow` or write into `~/.ssh` on the host running the server.
/// Passing the returned path (not the caller's spelling) to the child means
/// the child cannot resolve a relative path against a different directory.
/// The refusal is worded the same whether or not the path exists, so it is
/// not an oracle for files outside the roots.
pub(crate) fn validate_path(path: &str, param_name: &str) -> Result<String, String> {
    if path.is_empty() {
        return Err(format!("{param_name} must not be empty"));
    }
    reject_flag_like(path, param_name)?;
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
    let resolved = canonicalise_with_tail(&landed);
    if roots.iter().any(|root| resolved.starts_with(root)) {
        return resolved
            .into_os_string()
            .into_string()
            .map_err(|_| format!("{param_name} '{path}' is not valid UTF-8 once resolved"));
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

/// Whether a probe target names a local file rather than a URL or a
/// `host[:port]`.
///
/// `https://` targets are URLs. Anything with a path separator is a file.
/// A bare name is a file when it exists under the first root, which is the
/// child's working directory, so this agrees with how the CLI decides.
pub(crate) fn target_is_file(target: &str) -> bool {
    if target.starts_with("https://") || target.starts_with("http://") {
        return false;
    }
    if target.contains('/') || target.contains('\\') {
        return true;
    }
    primary_root().is_some_and(|root| root.join(target).exists())
}

/// Validate a probe target and return the form to pass to the child: URLs
/// and hostnames unchanged, file paths confined and made absolute with
/// [`validate_path`].
pub(crate) fn resolve_target(target: &str) -> Result<String, String> {
    validate_target(target)?;
    if target_is_file(target) {
        validate_path(target, "target")
    } else {
        Ok(target.to_string())
    }
}

/// Validate a free form value that reaches the subprocess argv (Vault mount,
/// role, TTL, serial, KV path, key names, SAN entries, HTTP header values).
/// Rejects flag lookalikes, control characters and absurd lengths.
pub(crate) fn validate_arg(value: &str, param_name: &str) -> Result<(), String> {
    const MAX_LEN: usize = 1024;
    reject_flag_like(value, param_name)?;
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

/// Parse a TLS version parameter into the CLI's own enum, so the MCP layer
/// accepts exactly the versions the CLI does and can compare them with `Ord`.
pub(crate) fn validate_tls_version(version: &str) -> Result<dcert::cli::TlsVersionArg, String> {
    use clap::ValueEnum;
    dcert::cli::TlsVersionArg::from_str(version, true)
        .map_err(|_| format!("Invalid TLS version '{version}': must be \"1.2\" or \"1.3\""))
}

/// Validate a Vault KV engine version parameter: only 1 and 2 exist.
pub(crate) fn validate_kv_version(kv_version: u8) -> Result<(), String> {
    if (1..=2).contains(&kv_version) {
        Ok(())
    } else {
        Err(format!("kv_version must be 1 or 2, got {kv_version}"))
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
