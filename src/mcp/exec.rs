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

/// Take a subprocess slot, waiting at most the subprocess timeout. Without
/// the bound a burst of calls would queue behind slow probes indefinitely;
/// with it the caller gets a clear "busy" answer instead.
pub(crate) async fn acquire_permit(config: &McpConfig) -> Result<tokio::sync::SemaphorePermit<'static>, String> {
    acquire_within(&SUBPROCESS_SEMAPHORE, config.subprocess_timeout).await
}

/// Take a permit from `semaphore`, waiting at most `wait`.
pub(crate) async fn acquire_within(
    semaphore: &Semaphore,
    wait: std::time::Duration,
) -> Result<tokio::sync::SemaphorePermit<'_>, String> {
    match tokio::time::timeout(wait, semaphore.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err("Subprocess semaphore closed".to_string()),
        Err(_) => Err(format!(
            "server busy: every subprocess slot stayed taken for {}s; retry later",
            wait.as_secs_f32()
        )),
    }
}

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

/// Whether `DCERT_MCP_DEBUG` asks for `--debug` on every subprocess.
///
/// Only the usual truthy spellings count (`1`, `true`, `yes`, `on`, in any
/// case); `0`, `false` or an empty value leave debugging off, so an operator
/// who sets the variable to disable it gets what they asked for.
pub(crate) fn debug_enabled() -> bool {
    debug_enabled_from(std::env::var("DCERT_MCP_DEBUG").ok().as_deref())
}

/// Pure form of [`debug_enabled`], for tests.
pub(crate) fn debug_enabled_from(value: Option<&str>) -> bool {
    value
        .map(str::trim)
        .is_some_and(|v| ["1", "true", "yes", "on"].iter().any(|t| v.eq_ignore_ascii_case(t)))
}

/// Build and spawn the dcert child process the one way every tool uses.
///
/// Every spawn site goes through here so the safety properties hold for all
/// of them:
///
/// - stdin is `/dev/null`. The MCP server's own stdin carries the JSON-RPC
///   stream, and a child that inherited it (and then prompted, as the Vault
///   subcommands can) would swallow protocol frames and read them as answers.
/// - `kill_on_drop` is set, so a tool future that is cancelled (client
///   disconnect, server shutdown) takes the child with it rather than leaving
///   an orphan running against a remote host.
/// - stdout and stderr are piped and drained by [`run_child_with_timeout`].
/// - the working directory is the first allowed file root.
///
/// The child inherits the parent environment (proxy variables, CA bundle
/// paths); `env_vars` adds per call secrets that must not travel in argv.
pub(crate) fn spawn_dcert(
    config: &McpConfig,
    args: &[&str],
    env_vars: &[(&str, &str)],
) -> Result<tokio::process::Child, String> {
    let mut cmd = Command::new(&config.dcert_binary);
    // Run in the first allowed root so the child resolves any relative path
    // exactly as `validate_path` did.
    if let Some(root) = crate::validate::primary_root() {
        cmd.current_dir(root);
    }
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    // The server's own settings, including secrets such as
    // DCERT_MCP_AUTH_TOKEN, are of no use to the CLI and must not reach it.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("DCERT_MCP_") {
            cmd.env_remove(&name);
        }
    }
    // The child enforces the same destination policy on the sockets it opens
    // and on AIA fetches. Both variables are always set so an inherited value
    // can never weaken the server's policy.
    cmd.env(
        dcert::netpolicy::ALLOWED_TARGETS_ENV,
        config.destinations.allow_list_env(),
    )
    .env(
        dcert::netpolicy::DENY_PRIVATE_TARGETS_ENV,
        if config.destinations.denies_private() { "1" } else { "0" },
    );
    for (key, value) in env_vars {
        cmd.env(key, value);
    }
    cmd.spawn()
        .map_err(|e| format!("Failed to run dcert at {}: {}", config.dcert_binary.display(), e))
}

/// Argument vector for a subcommand that takes a target: the subcommand
/// first, then `options`, then `--` and the target. The explicit subcommand
/// means a target can never be routed as one (a host called `kb`), and `--`
/// means it can never be parsed as a flag.
pub(crate) fn target_args(subcommand: &str, options: Vec<String>, target: &str) -> Vec<String> {
    let mut args = Vec::with_capacity(options.len() + 3);
    args.push(subcommand.to_string());
    args.extend(options);
    args.extend(["--".to_string(), target.to_string()]);
    args
}

/// What a dcert run produced: stdout, stderr and the exit code, or why it
/// could not run at all.
pub(crate) type RunOutcome = Result<(String, String, i32), String>;

/// One dcert run: the argument vector (subcommand first) and the per call
/// environment that carries secrets, which never travel in argv.
#[derive(Debug)]
pub(crate) struct Invocation<'a> {
    args: Vec<String>,
    env: Vec<(&'a str, &'a str)>,
}

impl<'a> Invocation<'a> {
    pub(crate) fn new<S: Into<String>>(args: impl IntoIterator<Item = S>) -> Self {
        Self {
            args: args.into_iter().map(Into::into).collect(),
            env: Vec::new(),
        }
    }

    pub(crate) fn env(mut self, vars: &[(&'a str, &'a str)]) -> Self {
        self.env.extend_from_slice(vars);
        self
    }

    fn subcommand(&self) -> &str {
        self.args.first().map_or("", String::as_str)
    }
}

/// The shared flags a subcommand accepts: `(--debug, --timeout and
/// --read-timeout)`.
fn shared_flags(subcommand: &str) -> (bool, bool) {
    match subcommand {
        // The server spawns `policy` only as `policy test`.
        "check" | "diagnose" | "verify-key" | "tls-scan" | "policy" => (true, true),
        "vault" => (true, false),
        _ => (false, false),
    }
}

/// Add `--debug` (when `debug`), `--timeout` and `--read-timeout` where the
/// subcommand accepts them and the caller did not set them. They go before
/// any `--`, after which every argument is a target.
pub(crate) fn inject_flags(args: &[String], debug: bool, timeout: &str, read_timeout: &str) -> Vec<String> {
    let (takes_debug, takes_timeouts) = shared_flags(args.first().map_or("", String::as_str));
    let split = args.iter().position(|a| a == "--").unwrap_or(args.len());
    let (options, targets) = args.split_at(split);
    let mut full = options.to_vec();
    // Tool arguments use both `--flag value` and `--flag=value`.
    let has = |flag: &str| {
        options
            .iter()
            .any(|a| a == flag || a.strip_prefix(flag).is_some_and(|rest| rest.starts_with('=')))
    };
    if takes_debug && debug && !has("--debug") {
        full.push("--debug".to_string());
    }
    if takes_timeouts {
        for (flag, value) in [("--timeout", timeout), ("--read-timeout", read_timeout)] {
            if !has(flag) {
                full.push(flag.to_string());
                full.push(value.to_string());
            }
        }
    }
    full.extend_from_slice(targets);
    full
}

/// Run dcert once and return (stdout, stderr, exit_code).
///
/// The one subprocess runner: it holds a concurrency permit for the life of
/// the child, injects `--debug` (when `DCERT_MCP_DEBUG` is truthy) and the
/// configured `--timeout` and `--read-timeout` wherever the subcommand takes
/// them, and enforces the subprocess timeout. All parameter validation
/// happens in the caller first, so a rejected call never holds a permit.
///
/// The subprocess inherits the parent environment (proxy variables, CA
/// bundle paths) apart from the server's own `DCERT_MCP_*` settings; see
/// [`spawn_dcert`].
pub(crate) async fn run_dcert(invocation: Invocation<'_>, config: &McpConfig) -> RunOutcome {
    let _permit = acquire_permit(config).await?;
    debug_assert!(
        !invocation.subcommand().is_empty(),
        "an invocation names its subcommand"
    );
    let args = inject_flags(
        &invocation.args,
        debug_enabled(),
        &config.connection_timeout.to_string(),
        &config.read_timeout.to_string(),
    );
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut child = spawn_dcert(config, &args, &invocation.env)?;
    run_child_with_timeout(&mut child, config).await
}

/// Exit code reported when the child died from a signal rather than exiting.
pub(crate) const EXIT_SIGNALLED: i32 = 128;

/// Wait for a child process with a timeout, reading both pipes concurrently
/// so a chatty child can never block on a full pipe, and killing it on
/// timeout so no orphan is left behind. Output is capped while it streams,
/// not after it has been buffered.
pub(crate) async fn run_child_with_timeout(child: &mut tokio::process::Child, config: &McpConfig) -> RunOutcome {
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
