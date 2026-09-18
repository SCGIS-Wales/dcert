//! Running the dcert CLI as a bounded, supervised subprocess.

use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Semaphore;

use crate::config::{McpConfig, format_timeout_error};

/// Maximum subprocess output size (10 MB) to prevent memory exhaustion.
pub(crate) const MAX_OUTPUT_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of concurrent subprocess invocations.
/// Prevents resource exhaustion when many MCP tool calls arrive simultaneously.
pub(crate) const MAX_CONCURRENT_SUBPROCESSES: usize = 10;

/// Global semaphore for subprocess concurrency limiting.
pub(crate) static SUBPROCESS_SEMAPHORE: std::sync::LazyLock<Arc<Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_SUBPROCESSES)));

/// Truncate subprocess output if it exceeds the maximum allowed size.
/// Walks back to a UTF-8 char boundary so the truncated output never splits a
/// multi-byte character.
pub(crate) fn truncate_output(output: String) -> String {
    if output.len() > MAX_OUTPUT_SIZE {
        let boundary = output.floor_char_boundary(MAX_OUTPUT_SIZE);
        let mut truncated = output[..boundary].to_string();
        truncated.push_str("\n--- output truncated (exceeded 10 MB limit) ---");
        truncated
    } else {
        output
    }
}

/// Run dcert with given arguments and return (stdout, stderr, exit_code).
///
/// Always passes `--debug` so MCP tool responses include diagnostic info.
/// Passes `--timeout` and `--read-timeout` from the MCP config to the subprocess.
/// Enforces a subprocess timeout to prevent indefinite hangs from slow or unreachable targets.
/// Acquires a semaphore permit to limit concurrent subprocess invocations.
///
/// Note: The subprocess inherits all parent environment variables (we do NOT call
/// `.env_clear()` or `.env()` on the Command). This is required for proxy support —
/// HTTPS_PROXY, HTTP_PROXY, NO_PROXY, SSL_CERT_FILE, and SSL_CERT_DIR are forwarded
/// automatically to the dcert CLI subprocess.
pub(crate) async fn run_dcert(args: &[&str], config: &McpConfig) -> Result<(String, String, i32), String> {
    run_dcert_with_env(args, config, None).await
}

/// Run dcert with optional environment variables for passing secrets securely.
/// Secrets like cert_password are passed via env vars instead of CLI args to avoid
/// exposing them in process listings (ps aux, /proc/<pid>/cmdline).
pub(crate) async fn run_dcert_with_env(
    args: &[&str],
    config: &McpConfig,
    env_vars: Option<&[(&str, &str)]>,
) -> Result<(String, String, i32), String> {
    let _permit = SUBPROCESS_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| "Subprocess semaphore closed".to_string())?;

    // Only include --debug when explicitly enabled via DCERT_MCP_DEBUG env var
    let mut full_args: Vec<&str> = Vec::with_capacity(args.len() + 5);
    full_args.extend_from_slice(args);
    if std::env::var("DCERT_MCP_DEBUG").is_ok() && !full_args.contains(&"--debug") {
        full_args.push("--debug");
    }

    // Pass connection and read timeouts to the dcert subprocess
    let timeout_str = config.connection_timeout.to_string();
    let read_timeout_str = config.read_timeout.to_string();
    if !full_args.contains(&"--timeout") {
        full_args.push("--timeout");
        full_args.push(&timeout_str);
    }
    if !full_args.contains(&"--read-timeout") {
        full_args.push("--read-timeout");
        full_args.push(&read_timeout_str);
    }

    let mut cmd = Command::new(&config.dcert_binary);
    cmd.args(&full_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Set additional env vars (e.g., DCERT_CERT_PASSWORD for mTLS)
    if let Some(vars) = env_vars {
        for (key, value) in vars {
            cmd.env(key, value);
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to run dcert at {}: {}", config.dcert_binary.display(), e))?;

    run_child_with_timeout(&mut child, config).await
}

/// Run dcert without --debug and without --timeout/--read-timeout flags.
/// Used for subcommands (convert, verify-key) that don't support connection timeouts.
/// Acquires a semaphore permit to limit concurrent subprocess invocations.
/// Optionally accepts environment variables (e.g., for passing passwords securely).
///
/// Note: The subprocess inherits all parent environment variables including proxy
/// settings. See `run_dcert()` for details.
pub(crate) async fn run_dcert_raw(
    args: &[&str],
    config: &McpConfig,
    env_vars: Option<&[(&str, &str)]>,
) -> Result<(String, String, i32), String> {
    // The semaphore permit binds to `_permit` and is released when this
    // function returns (success, error, or `?` propagation). It bounds
    // concurrent subprocesses to `MAX_CONCURRENT_SUBPROCESSES` so a flood
    // of MCP tool calls cannot exhaust the host's process table. All
    // parameter validation (paths, passwords, aliases) happens in the
    // caller before we get here, so failed validation never holds a permit.
    let _permit = SUBPROCESS_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| "Subprocess semaphore closed".to_string())?;

    let mut cmd = Command::new(&config.dcert_binary);
    cmd.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if let Some(vars) = env_vars {
        for (key, value) in vars {
            cmd.env(key, value);
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to run dcert at {}: {}", config.dcert_binary.display(), e))?;

    run_child_with_timeout(&mut child, config).await
}

/// Wait for a child process with timeout, explicitly killing it on timeout
/// to prevent orphaned processes.
pub(crate) async fn run_child_with_timeout(
    child: &mut tokio::process::Child,
    config: &McpConfig,
) -> Result<(String, String, i32), String> {
    // Take the pipes so we can read them separately from waiting
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    // Wait for the child with a timeout
    match tokio::time::timeout(config.subprocess_timeout, child.wait()).await {
        Ok(result) => {
            let status = result.map_err(|e| format!("Failed waiting for dcert: {e}"))?;

            // Read pipes after the process has exited
            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();
            if let Some(ref mut pipe) = stdout_pipe {
                let _ = tokio::io::AsyncReadExt::read_to_end(pipe, &mut stdout_buf).await;
            }
            if let Some(ref mut pipe) = stderr_pipe {
                let _ = tokio::io::AsyncReadExt::read_to_end(pipe, &mut stderr_buf).await;
            }

            let stdout = truncate_output(String::from_utf8_lossy(&stdout_buf).to_string());
            let stderr = truncate_output(String::from_utf8_lossy(&stderr_buf).to_string());
            let code = status.code().unwrap_or(2);
            Ok((stdout, stderr, code))
        }
        Err(_) => {
            // Explicitly kill the child process on timeout to prevent orphaned processes
            let _ = child.kill().await;
            Err(format_timeout_error(config))
        }
    }
}
