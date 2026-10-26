//! Wall clock deadlines for blocking network exchanges.
//!
//! A socket read timeout bounds one read, not an exchange: a peer that sends
//! one byte every second keeps a handshake, a STARTTLS dialogue or an HTTP
//! read alive forever. [`DeadlineGuard`] bounds the whole exchange instead. A
//! watchdog thread shuts the socket down when the deadline passes, which
//! wakes any blocked read or write (including one inside an OpenSSL
//! handshake), and the caller then reports a timeout rather than whatever
//! error the half closed socket produced.

use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

/// Arms a watchdog over one TCP connection. Dropping the guard disarms it.
#[derive(Debug)]
pub struct DeadlineGuard {
    expired: Arc<AtomicBool>,
    budget: Duration,
    /// Dropping the sender wakes the watchdog, which then exits quietly.
    _cancel: Option<Sender<()>>,
}

impl DeadlineGuard {
    /// Shut `stream` down at `deadline`. `budget` is the total allowance,
    /// quoted in timeout messages. A socket that cannot be cloned gets no
    /// watchdog; its per read timeouts still apply.
    pub fn arm(stream: &TcpStream, deadline: Instant, budget: Duration) -> Self {
        let expired = Arc::new(AtomicBool::new(false));
        let Ok(clone) = stream.try_clone() else {
            return Self {
                expired,
                budget,
                _cancel: None,
            };
        };
        let (tx, rx) = channel::<()>();
        let flag = Arc::clone(&expired);
        std::thread::spawn(move || {
            let wait = deadline.saturating_duration_since(Instant::now());
            if let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(wait) {
                flag.store(true, Ordering::SeqCst);
                let _ = clone.shutdown(Shutdown::Both);
            }
        });
        Self {
            expired,
            budget,
            _cancel: Some(tx),
        }
    }

    /// A guard that never fires, for connections without a deadline.
    pub fn disarmed() -> Self {
        Self {
            expired: Arc::new(AtomicBool::new(false)),
            budget: Duration::ZERO,
            _cancel: None,
        }
    }

    /// Whether the deadline passed and the socket was shut down.
    pub fn expired(&self) -> bool {
        self.expired.load(Ordering::SeqCst)
    }

    /// The error to report when the deadline cut `phase` short.
    pub fn timeout_error(&self, phase: &str) -> anyhow::Error {
        anyhow::anyhow!(
            "timed out during {phase}: the probe exceeded its {}s budget (--timeout plus --read-timeout)",
            self.budget.as_secs()
        )
    }
}

/// The probe budget: the connect timeout plus the read timeout.
pub fn probe_budget(timeout_secs: u64, read_timeout_secs: u64) -> Duration {
    Duration::from_secs(timeout_secs.saturating_add(read_timeout_secs.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    #[test]
    fn a_blocked_read_ends_at_the_deadline() {
        let (mut client, _server) = pair();
        let started = Instant::now();
        let guard = DeadlineGuard::arm(
            &client,
            Instant::now() + Duration::from_millis(300),
            Duration::from_secs(1),
        );
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "the shut down socket reads as closed");
        assert!(guard.expired());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(
            guard
                .timeout_error("the TLS handshake")
                .to_string()
                .contains("1s budget")
        );
    }

    #[test]
    fn dropping_the_guard_disarms_it() {
        let (client, _server) = pair();
        let guard = DeadlineGuard::arm(
            &client,
            Instant::now() + Duration::from_millis(100),
            Duration::from_secs(1),
        );
        drop(guard);
        std::thread::sleep(Duration::from_millis(300));
        client.set_nonblocking(true).expect("nonblocking");
        let mut buf = [0u8; 1];
        let err = (&client).read(&mut buf).expect_err("still open, nothing to read");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn budget_adds_both_timeouts() {
        assert_eq!(probe_budget(10, 5), Duration::from_secs(15));
        assert_eq!(probe_budget(10, 0), Duration::from_secs(11));
        assert!(!DeadlineGuard::disarmed().expired());
    }
}
