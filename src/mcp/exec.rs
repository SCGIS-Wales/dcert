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

/// Decode captured bytes, marking the result when the stream was cut at the
/// cap. Without the marker a child that emits exactly the limit would have its
/// output silently shortened, which reads as a complete but wrong answer.
fn decode_capped(buf: &[u8], dropped: bool) -> String {
    let mut text = String::from_utf8_lossy(buf).into_owned();
    if dropped {
        text.push_str("\n--- output truncated (exceeded 10 MB limit) ---");
    }
    text
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

/// Exit code reported when the child died from a signal rather than exiting.
pub(crate) const EXIT_SIGNALLED: i32 = 128;

/// Wait for a child process with a timeout, reading both pipes concurrently
/// so a chatty child can never block on a full pipe, and killing it on
/// timeout so no orphan is left behind. Output is capped while it streams,
/// not after it has been buffered.
pub(crate) async fn run_child_with_timeout(
    child: &mut tokio::process::Child,
    config: &McpConfig,
) -> Result<(String, String, i32), String> {
    use tokio::io::AsyncReadExt;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    /// Read a pipe to EOF, keeping at most [`MAX_OUTPUT_SIZE`] bytes and
    /// discarding the rest.
    ///
    /// Reading only up to the cap and then dropping the pipe would close the
    /// read end while the child is still writing: the child dies of SIGPIPE
    /// and is reported as signalled, which reads as a crash rather than as
    /// truncated output. Draining to EOF lets the child finish and exit
    /// normally. The kept bytes are capped as they stream, so a chatty child
    /// still cannot grow the buffer without bound.
    ///
    /// Returns the kept bytes, whether anything was discarded, and any read
    /// error.
    async fn drain_capped<R>(pipe: Option<R>) -> (Vec<u8>, bool, Option<String>)
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let Some(mut pipe) = pipe else {
            return (Vec::new(), false, None);
        };
        let mut kept = Vec::new();
        let mut dropped = false;
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk).await {
                Ok(0) => return (kept, dropped, None),
                Ok(n) => {
                    let room = MAX_OUTPUT_SIZE.saturating_sub(kept.len());
                    if room < n {
                        dropped = true;
                    }
                    if room > 0 {
                        kept.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
                Err(e) => return (kept, dropped, Some(e.to_string())),
            }
        }
    }

    let work = async {
        let (out, err, status) = tokio::join!(drain_capped(stdout_pipe), drain_capped(stderr_pipe), child.wait());
        (out, err, status)
    };

    match tokio::time::timeout(config.subprocess_timeout, work).await {
        Ok(((stdout_buf, stdout_dropped, stdout_err), (stderr_buf, stderr_dropped, stderr_err), status)) => {
            let status = status.map_err(|e| format!("Failed waiting for dcert: {e}"))?;
            let stdout = truncate_output(decode_capped(&stdout_buf, stdout_dropped));
            let mut stderr = truncate_output(decode_capped(&stderr_buf, stderr_dropped));
            for (name, e) in [("stdout", stdout_err), ("stderr", stderr_err)] {
                if let Some(e) = e {
                    stderr.push_str(&format!("\n--- note: reading {name} failed: {e} ---"));
                }
            }
            let code = match status.code() {
                Some(c) => c,
                None => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        stderr.push_str(&format!(
                            "\n--- note: dcert terminated by signal {} ---",
                            status.signal().unwrap_or(0)
                        ));
                    }
                    EXIT_SIGNALLED
                }
            };
            Ok((stdout, stderr, code))
        }
        Err(_) => {
            if let Err(e) = child.kill().await {
                tracing::warn!(error = %e, "failed to kill timed out dcert subprocess");
            }
            Err(format_timeout_error(config))
        }
    }
}

/// Assemble a tool response from subprocess output: stdout, then stderr under
/// a banner, then the exit code unless it is one the tool treats as normal.
pub(crate) fn format_tool_output(stdout: String, stderr: &str, code: i32, banner: &str, ok_codes: &[i32]) -> String {
    let mut output = stdout;
    if !stderr.is_empty() {
        output.push_str("\n--- ");
        output.push_str(banner);
        output.push_str(" ---\n");
        output.push_str(stderr);
    }
    if !ok_codes.contains(&code) {
        output.push_str(&format!("\n--- exit code: {code} ---"));
    }
    output
}
