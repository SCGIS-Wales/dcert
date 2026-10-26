//! Name resolution with a deadline and connection attempts over every
//! resolved address.
//!
//! `getaddrinfo` has no timeout of its own, and taking only its first answer
//! fails a dual stack host whenever that one address is unreachable. These
//! helpers bound the lookup and walk every address in the resolver's order
//! (RFC 6724, IPv6 first where the host prefers it), splitting the connect
//! timeout between them, and name every attempt when all of them fail. The
//! probe, the proxy dial and the OCSP client share them.

use anyhow::Result;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::{Duration, Instant};

/// Shortest connect attempt given to one address when the timeout is shared.
pub const MIN_PER_ADDRESS: Duration = Duration::from_secs(1);

/// Resolve `host:port` through the system resolver within `timeout`.
/// Returns every address and the time the lookup took in milliseconds.
pub fn resolve_all(host: &str, port: u16, timeout: Duration) -> Result<(Vec<SocketAddr>, u128)> {
    resolve_with(host, port, timeout, |h, p| {
        (h.as_str(), p).to_socket_addrs().map(Iterator::collect)
    })
}

/// [`resolve_all`] with an injectable resolver, run on its own thread so a
/// lookup that never returns cannot block the caller past `timeout`.
pub fn resolve_with<F>(host: &str, port: u16, timeout: Duration, resolver: F) -> Result<(Vec<SocketAddr>, u128)>
where
    F: FnOnce(String, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    let started = Instant::now();
    let (tx, rx) = channel();
    let owned = host.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(resolver(owned, port));
    });
    let wait = timeout.max(MIN_PER_ADDRESS);
    let addrs = match rx.recv_timeout(wait) {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(e)) => anyhow::bail!("DNS resolution failed for '{host}': {e}"),
        Err(RecvTimeoutError::Timeout) => {
            anyhow::bail!("DNS resolution for '{host}' timed out after {}s", wait.as_secs())
        }
        Err(RecvTimeoutError::Disconnected) => anyhow::bail!("DNS resolution for '{host}' failed"),
    };
    if addrs.is_empty() {
        anyhow::bail!("DNS resolution failed for '{host}': no addresses returned");
    }
    Ok((addrs, started.elapsed().as_millis()))
}

/// The connect timeout each of `count` addresses gets: an equal share of
/// `total`, but at least [`MIN_PER_ADDRESS`] and at most `total`.
pub fn per_address_timeout(total: Duration, count: usize) -> Duration {
    let count = u32::try_from(count.max(1)).unwrap_or(u32::MAX);
    (total / count).max(MIN_PER_ADDRESS).min(total.max(MIN_PER_ADDRESS))
}

/// Connect to the first of `addrs` that accepts, in order. `admit` may veto
/// an address before any packet is sent (the destination policy); a vetoed
/// address counts as a failed attempt. On total failure the error names the
/// host and every attempt with its reason.
pub fn connect_first(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    timeout: Duration,
    admit: impl Fn(&SocketAddr) -> Result<()>,
) -> Result<(TcpStream, SocketAddr)> {
    let each = per_address_timeout(timeout, addrs.len());
    let mut failures = Vec::new();
    for addr in addrs {
        if let Err(e) = admit(addr) {
            failures.push((*addr, format!("{e}")));
            continue;
        }
        match TcpStream::connect_timeout(addr, each) {
            Ok(stream) => return Ok((stream, *addr)),
            Err(e) => failures.push((*addr, describe(&e, each))),
        }
    }
    Err(match failures.as_slice() {
        [(_, reason)] if reason == "refused" => {
            anyhow::anyhow!("TCP connection refused by {host}:{port} (port may not be open)")
        }
        [(_, reason)] => anyhow::anyhow!("TCP connection to {host}:{port} {reason}"),
        _ => anyhow::anyhow!(
            "TCP connection to {host}:{port} failed on every address ({})",
            failures
                .iter()
                .map(|(a, r)| format!("{a}: {r}"))
                .collect::<Vec<_>>()
                .join("; ")
        ),
    })
}

fn describe(e: &io::Error, timeout: Duration) -> String {
    match e.kind() {
        io::ErrorKind::TimedOut => format!("timed out after {}s", timeout.as_secs()),
        io::ErrorKind::ConnectionRefused => "refused".to_string(),
        _ => format!("failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn closed_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port()
    }

    #[test]
    fn a_hanging_lookup_times_out() {
        let started = Instant::now();
        let err = resolve_with("slow.example", 443, Duration::from_secs(1), |_, _| {
            std::thread::sleep(Duration::from_secs(5));
            Ok(Vec::new())
        })
        .expect_err("must time out");
        assert!(err.to_string().contains("timed out after 1s"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn an_empty_answer_is_an_error() {
        let err =
            resolve_with("none.example", 443, Duration::from_secs(1), |_, _| Ok(Vec::new())).expect_err("no addresses");
        assert!(err.to_string().contains("no addresses"), "{err}");
    }

    #[test]
    fn every_address_is_tried_in_order() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let open: SocketAddr = listener.local_addr().expect("addr");
        let closed: SocketAddr = format!("127.0.0.1:{}", closed_port()).parse().expect("addr");
        let (_, reached) = connect_first(
            "dual.example",
            open.port(),
            &[closed, open],
            Duration::from_secs(2),
            |_| Ok(()),
        )
        .expect("second address answers");
        assert_eq!(reached, open);
    }

    #[test]
    fn total_failure_names_every_attempt() {
        let a: SocketAddr = format!("127.0.0.1:{}", closed_port()).parse().expect("addr");
        let b: SocketAddr = format!("127.0.0.1:{}", closed_port()).parse().expect("addr");
        let err = connect_first("down.example", 443, &[a, b], Duration::from_secs(2), |_| Ok(()))
            .expect_err("all closed")
            .to_string();
        assert!(err.contains(&a.to_string()) && err.contains(&b.to_string()), "{err}");
        assert!(err.contains("every address"), "{err}");
    }

    #[test]
    fn a_vetoed_address_is_skipped_and_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let open = listener.local_addr().expect("addr");
        let err = connect_first("policy.example", open.port(), &[open], Duration::from_secs(1), |_| {
            anyhow::bail!("refused by policy")
        })
        .expect_err("vetoed")
        .to_string();
        assert!(err.contains("refused by policy"), "{err}");
    }

    #[test]
    fn per_address_timeout_shares_but_never_below_one_second() {
        assert_eq!(per_address_timeout(Duration::from_secs(10), 2), Duration::from_secs(5));
        assert_eq!(per_address_timeout(Duration::from_secs(2), 8), MIN_PER_ADDRESS);
        assert_eq!(per_address_timeout(Duration::from_secs(10), 1), Duration::from_secs(10));
    }
}
