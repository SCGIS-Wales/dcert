//! Protocol version, cipher suite and group enumeration (`dcert tls-scan`).
//!
//! The scan first offers each protocol version on its own. For every
//! version the server accepts it then offers the suites the linked OpenSSL
//! can offer, one per handshake, and finally each known key exchange group
//! at the newest accepted version. Handshakes run a few at a time and stop
//! at a fixed budget, so a scan is bounded in time and in load on the server.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde::Serialize;

use crate::ciphers::{Cipher, NegotiatedCipher, Protocol};
use crate::cli::TlsVersionArg;
use crate::tls::{PqProbeRequest, ScanHandshake, TlsProbeOptions, scan_handshake};

/// What the scan may do.
#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    /// Offer TLS 1.0 and 1.1 too.
    pub allow_legacy_tls: bool,
    /// Most handshakes in total.
    pub max_handshakes: usize,
    /// Handshakes run at once.
    pub concurrency: usize,
}

/// One protocol version: whether the server accepts it and, when it does,
/// every suite tried at that version.
#[derive(Debug, Serialize)]
pub struct VersionScan {
    /// `1.0`, `1.1`, `1.2` or `1.3`.
    pub version: &'static str,
    pub accepted: bool,
    /// What the version handshake negotiated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiated: Option<ScanHandshake>,
    /// Why the server refused the version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<String>,
    /// Every suite offered at this version, accepted or not.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ciphers: Vec<CipherScan>,
}

/// One suite offered on its own.
#[derive(Debug, Serialize)]
pub struct CipherScan {
    pub cipher: NegotiatedCipher,
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<String>,
}

/// Whether the server agreed to a key exchange group offered on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupStatus {
    Accepted,
    Rejected,
    /// The linked OpenSSL does not implement the group.
    NotTestable,
}

/// One key exchange group offered on its own.
#[derive(Debug, Serialize)]
pub struct GroupScan {
    pub group: &'static str,
    pub status: GroupStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<String>,
}

/// The full scan.
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub target: String,
    /// Newest version first.
    pub versions: Vec<VersionScan>,
    /// Groups tried at the newest accepted version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups_version: Option<&'static str>,
    pub groups: Vec<GroupScan>,
    pub handshakes: usize,
    pub max_handshakes: usize,
    /// The budget ran out before every suite and group was tried.
    pub truncated: bool,
}

impl ScanReport {
    /// Whether any version was accepted.
    pub fn reachable(&self) -> bool {
        self.versions.iter().any(|v| v.accepted)
    }
}

/// The alert or local reason in an OpenSSL handshake error, e.g.
/// `handshake failure` from `... sslv3 alert handshake failure ...`.
pub fn alert_reason(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    for marker in ["sslv3 alert ", "tlsv1 alert ", "tlsv13 alert "] {
        if let Some(start) = lower.find(marker) {
            let rest = &lower[start + marker.len()..];
            let end = rest.find([':', '(', '\n']).unwrap_or(rest.len());
            return rest[..end].trim().to_string();
        }
    }
    for local in [
        "no protocols available",
        "no ciphers available",
        "no shared cipher",
        "wrong version number",
        "unsupported protocol",
        "unexpected eof",
    ] {
        if lower.contains(local) {
            return local.to_string();
        }
    }
    error.lines().next().unwrap_or(error).trim().to_string()
}

/// Run `work` over `items` with at most `workers` threads, results in input
/// order.
pub(crate) fn run_bounded<T: Sync, R: Send>(items: &[T], workers: usize, work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let mut results: Vec<Option<R>> = Vec::new();
    results.resize_with(items.len(), || None);
    let slots = std::sync::Mutex::new(&mut results);
    std::thread::scope(|scope| {
        for _ in 0..workers.max(1).min(items.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    let result = work(item);
                    if let Ok(mut slots) = slots.lock() {
                        slots[i] = Some(result);
                    }
                }
            });
        }
    });
    results.into_iter().flatten().collect()
}

/// The versions to try, newest first.
fn versions(limits: ScanLimits) -> Vec<TlsVersionArg> {
    [
        TlsVersionArg::Tls1_3,
        TlsVersionArg::Tls1_2,
        TlsVersionArg::Tls1_1,
        TlsVersionArg::Tls1_0,
    ]
    .into_iter()
    .filter(|v| limits.allow_legacy_tls || !v.is_legacy())
    .collect()
}

/// Suites worth offering at `version`: the linked OpenSSL offers them and
/// the version can carry them (TLS 1.0 and 1.1 have no AEAD or SHA-2 MACs).
fn suites_for(version: TlsVersionArg) -> Vec<&'static Cipher> {
    let family = if version == TlsVersionArg::Tls1_3 {
        Protocol::Tls13
    } else {
        Protocol::Tls12
    };
    crate::ciphers::all()
        .iter()
        .filter(|c| c.protocol == family && c.openssl.is_some() && c.offerable())
        .filter(|c| !version.is_legacy() || !(c.aead || c.mac.starts_with("SHA2") || c.mac.starts_with("SHA3")))
        .collect()
}

/// Every TLS 1.3 suite the linked OpenSSL implements, colon separated.
pub(crate) fn all_tls13_suites() -> String {
    suites_for(TlsVersionArg::Tls1_3)
        .iter()
        .filter_map(|c| c.openssl)
        .collect::<Vec<_>>()
        .join(":")
}

/// The cipher string for TLS 1.2 and earlier: everything, at security level
/// 0 for the legacy versions.
pub(crate) fn broad_cipher_list(version: TlsVersionArg) -> &'static str {
    if version.is_legacy() { "ALL:@SECLEVEL=0" } else { "ALL" }
}

/// Run the scan against `target`. `base` carries the connection settings;
/// every handshake skips verification, since what is being asked is what
/// the server negotiates, not whether it is trusted.
pub fn scan(target: &str, req: &PqProbeRequest<'_>, base: &TlsProbeOptions<'_>, limits: ScanLimits) -> ScanReport {
    // Handshakes started so far; a handshake runs only while this stays
    // under the budget.
    let used = AtomicUsize::new(0);
    let take = || used.fetch_add(1, Ordering::Relaxed) < limits.max_handshakes;
    let mut truncated = false;
    let tls13_suites = all_tls13_suites();

    // 1. Each version on its own.
    let version_list = versions(limits);
    let mut versions_scanned: Vec<VersionScan> = run_bounded(&version_list, limits.concurrency, |&version| {
        if !take() {
            return None;
        }
        let list = broad_cipher_list(version);
        let probe = TlsProbeOptions {
            no_verify: true,
            min_tls: Some(version),
            max_tls: Some(version),
            cipher_list: Some(list),
            cipher_suites: Some(&tls13_suites),
            groups: None,
            ..*base
        };
        Some(match scan_handshake(req, &probe) {
            Ok(h) => VersionScan {
                version: version.number(),
                accepted: true,
                negotiated: Some(h),
                alert: None,
                ciphers: Vec::new(),
            },
            Err(e) => VersionScan {
                version: version.number(),
                accepted: false,
                negotiated: None,
                alert: Some(alert_reason(&e.to_string())),
                ciphers: Vec::new(),
            },
        })
    })
    .into_iter()
    .flatten()
    .collect();
    truncated |= versions_scanned.len() < version_list.len();

    // 2. Each suite on its own, per accepted version.
    for scanned in &mut versions_scanned {
        if !scanned.accepted {
            continue;
        }
        let Some(version) = version_list.iter().copied().find(|v| v.number() == scanned.version) else {
            continue;
        };
        let suites = suites_for(version);
        let results = run_bounded(&suites, limits.concurrency, |cipher| {
            if !take() {
                return None;
            }
            let name = cipher.openssl.unwrap_or(cipher.iana);
            let legacy_list;
            let (cipher_list, cipher_suites) = if version == TlsVersionArg::Tls1_3 {
                (broad_cipher_list(version), name)
            } else {
                legacy_list = if version.is_legacy() {
                    format!("{name}:@SECLEVEL=0")
                } else {
                    name.to_string()
                };
                (legacy_list.as_str(), tls13_suites.as_str())
            };
            let probe = TlsProbeOptions {
                no_verify: true,
                min_tls: Some(version),
                max_tls: Some(version),
                cipher_list: Some(cipher_list),
                cipher_suites: Some(cipher_suites),
                groups: None,
                ..*base
            };
            let offered = NegotiatedCipher::new(name, Some(cipher.iana), Some(cipher.code));
            Some(match scan_handshake(req, &probe) {
                Ok(h) => CipherScan {
                    cipher: h.cipher,
                    accepted: true,
                    group: h.group,
                    leaf_key: h.leaf_key,
                    alert: None,
                },
                Err(e) => CipherScan {
                    cipher: offered,
                    accepted: false,
                    group: None,
                    leaf_key: None,
                    alert: Some(alert_reason(&e.to_string())),
                },
            })
        });
        truncated |= results.iter().any(Option::is_none);
        scanned.ciphers = results.into_iter().flatten().collect();
    }

    // 3. Each group on its own, at the newest accepted version.
    let newest = versions_scanned
        .iter()
        .find(|v| v.accepted)
        .and_then(|v| version_list.iter().copied().find(|x| x.number() == v.version));
    let groups: Vec<GroupScan> = match newest {
        None => Vec::new(),
        Some(version) => {
            let names: Vec<&'static str> = crate::keyex::scan_groups().collect();
            let results = run_bounded(&names, limits.concurrency, |&group| {
                if !group_implemented(group) {
                    return Some(GroupScan {
                        group,
                        status: GroupStatus::NotTestable,
                        alert: None,
                    });
                }
                if !take() {
                    return None;
                }
                let probe = TlsProbeOptions {
                    no_verify: true,
                    min_tls: Some(version),
                    max_tls: Some(version),
                    cipher_list: Some(broad_cipher_list(version)),
                    cipher_suites: Some(&tls13_suites),
                    groups: Some(group),
                    ..*base
                };
                Some(match scan_handshake(req, &probe) {
                    Ok(_) => GroupScan {
                        group,
                        status: GroupStatus::Accepted,
                        alert: None,
                    },
                    Err(e) => GroupScan {
                        group,
                        status: GroupStatus::Rejected,
                        alert: Some(alert_reason(&e.to_string())),
                    },
                })
            });
            truncated |= results.iter().any(Option::is_none);
            results.into_iter().flatten().collect()
        }
    };

    ScanReport {
        target: target.to_string(),
        groups_version: newest.map(TlsVersionArg::number),
        versions: versions_scanned,
        groups,
        handshakes: used.load(Ordering::Relaxed).min(limits.max_handshakes),
        max_handshakes: limits.max_handshakes,
        truncated,
    }
}

/// Whether the linked OpenSSL knows `group`, so a refusal is the server's.
pub(crate) fn group_implemented(group: &str) -> bool {
    openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls())
        .and_then(|mut b| b.set_groups_list(group))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_reasons_are_short() {
        assert_eq!(
            alert_reason(
                "error:0A000410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:../ssl/record/rec_layer_s3.c:1599:SSL alert number 40"
            ),
            "handshake failure"
        );
        assert_eq!(
            alert_reason("error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:../ssl"),
            "protocol version"
        );
        assert_eq!(
            alert_reason("error:0A0000BF:SSL routines::no protocols available"),
            "no protocols available"
        );
        assert_eq!(alert_reason("connection refused\nmore"), "connection refused");
    }

    #[test]
    fn bounded_runs_keep_order_and_cover_every_item() {
        let items: Vec<u32> = (0..50).collect();
        let doubled = run_bounded(&items, 4, |n| n * 2);
        assert_eq!(doubled, items.iter().map(|n| n * 2).collect::<Vec<_>>());
        assert!(run_bounded(&Vec::<u32>::new(), 4, |n| *n).is_empty());
    }

    #[test]
    fn legacy_versions_only_with_the_flag_and_without_aead_suites() {
        let limits = ScanLimits {
            allow_legacy_tls: false,
            max_handshakes: 10,
            concurrency: 4,
        };
        assert_eq!(versions(limits), [TlsVersionArg::Tls1_3, TlsVersionArg::Tls1_2]);
        let legacy = ScanLimits {
            allow_legacy_tls: true,
            ..limits
        };
        assert_eq!(versions(legacy).len(), 4);
        assert!(suites_for(TlsVersionArg::Tls1_1).iter().all(|c| !c.aead));
        assert!(suites_for(TlsVersionArg::Tls1_2).iter().any(|c| c.code == 0xC02F));
        assert!(
            suites_for(TlsVersionArg::Tls1_3)
                .iter()
                .all(|c| c.protocol == Protocol::Tls13)
        );
    }

    #[test]
    fn classical_groups_are_implemented_and_nonsense_is_not() {
        assert!(group_implemented("X25519"));
        assert!(!group_implemented("NoSuchGroup"));
    }
}
