//! Root-CA trust classification.
//!
//! Determines whether a certificate chain anchors to a **publicly trusted**
//! root CA (one in a recognized public root program), a **private PKI**, or is
//! **self-signed**. The authoritative public-CA source is the Mozilla/CCADB
//! root set embedded via the `webpki-root-certs` crate. CCADB is the shared
//! backing database for the Mozilla, Microsoft, Apple and Google root programs,
//! so DigiCert, Amazon/AWS, Google Trust Services, Microsoft and Apple public
//! TLS roots, GlobalSign, Sectigo, Let's Encrypt, etc. are all included.
//!
//! Classification is a **local cryptographic chain verification** against that
//! embedded store (OpenSSL `X509StoreContext::verify_cert`), so it requires no
//! network and runs instantly across many certificates. Because the signature
//! must validate against an embedded public key, a private root that merely
//! shares a Distinguished Name with a public one cannot produce a false
//! positive. Certificate *validity* (expiry) is intentionally ignored here
//! (`NO_CHECK_TIME`) — this answers "is the root publicly trusted?", and dcert
//! reports expiry separately.
//!
//! Network access is **opt-in** (`--resolve-issuers`): for chains that do not
//! reach a public root it follows the AIA "CA Issuers" URLs to complete the
//! chain and to confirm a private CA backend is reachable. All network access
//! honours the standard forward-proxy environment variables via [`ProxyConfig`]
//! and uses a short, separate timeout.

use anyhow::Result;
use colored::*;
use openssl::hash::MessageDigest;
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509, X509Ref, X509StoreContext};
use std::collections::HashSet;
use std::time::Duration;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::cert::{fingerprint_hex, format_x509_name_with_keys as format_name};
use crate::debug::debug_log;
use crate::proxy::ProxyConfig;

/// Maximum issuer-chain hops to follow when resolving via AIA. Bounds work and
/// guards against pathological/looping AIA pointers.
const MAX_AIA_HOPS: usize = 4;

/// Maximum size (bytes) accepted for a fetched issuer certificate. AIA-served
/// certs are a few KB; this caps a misbehaving or hostile endpoint.
const MAX_ISSUER_BYTES: usize = 256 * 1024;

/// Cap on the CCADB root bundle download to bound memory if a hostile proxy
/// streams an oversized body. The real bundle is ~250 KB; 8 MB is generous.
const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

/// Upstream Mozilla/CCADB bundle used by `--refresh-public-roots`.
const CCADB_BUNDLE_URL: &str = "https://curl.se/ca/cacert.pem";

/// How a certificate chain's root CA is trusted.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootTrustClass {
    /// The chain verifies up to a root in the embedded public root store.
    PubliclyTrusted,
    /// The chain terminates in a private (non-public) root CA.
    PrivatePki,
    /// A single self-signed certificate (not issued by any CA).
    SelfSigned,
    /// The chain neither reaches a public root nor presents a self-signed root
    /// (an issuer is missing). Use `--resolve-issuers` to attempt completion.
    Incomplete,
    /// Trust could not be assessed (e.g. unparseable input).
    Unknown,
}

/// Chain-level root-CA trust assessment, surfaced in structured and pretty output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RootTrustInfo {
    pub classification: RootTrustClass,
    /// Convenience boolean: true only for [`RootTrustClass::PubliclyTrusted`].
    pub publicly_trusted: bool,
    /// Distinguished Name of the root the chain anchors to (public, or — when
    /// resolved — the private root).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_anchor_subject: Option<String>,
    /// SHA-256 fingerprint of that root CA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_anchor_sha256: Option<String>,
    /// Whether the anchoring root was present in the certificate(s) supplied
    /// (servers usually omit the root; PEM bundles may include it).
    pub anchor_present_in_chain: bool,
    /// Whether `--resolve-issuers` fetched issuer cert(s) over the network to
    /// complete the chain.
    pub chain_completed_via_aia: bool,
    /// For a private PKI probed via `--resolve-issuers`: whether the CA backend
    /// (AIA "CA Issuers" endpoint) was reachable. `None` when not probed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_backend_reachable: Option<bool>,
    /// Which public-root source was used: `embedded` or `embedded+refreshed`.
    pub source: &'static str,
    /// Short human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Options controlling the (opt-in) network behaviour of trust assessment.
#[derive(Debug, Clone, Copy)]
pub struct TrustOpts {
    pub resolve_issuers: bool,
    pub issuer_timeout: Duration,
    pub debug: bool,
}

/// The embedded public-root trust store plus a fast fingerprint set for
/// per-certificate "is this a public root?" checks. Built once per invocation.
pub struct PublicRoots {
    store: X509Store,
    fingerprints: HashSet<Vec<u8>>,
    source: &'static str,
}

impl std::fmt::Debug for PublicRoots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicRoots")
            .field("roots", &self.fingerprints.len())
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl PublicRoots {
    /// Load the public root set. With `refresh`, unions the upstream
    /// Mozilla/CCADB bundle into the embedded set (best-effort: a refresh
    /// failure falls back to the embedded set with a warning).
    pub fn load(refresh: bool, proxy: &ProxyConfig, timeout: Duration, debug: bool) -> Result<Self> {
        let mut certs = embedded_roots();
        let mut source: &'static str = "embedded";
        if refresh {
            match refresh_public_roots(proxy, timeout, debug) {
                Ok(extra) => {
                    debug_log!(
                        debug,
                        "Public roots refreshed: {} embedded + {} from CCADB bundle",
                        certs.len(),
                        extra.len()
                    );
                    certs.extend(extra);
                    source = "embedded+refreshed";
                }
                Err(e) => {
                    if let Some((cached, age)) = read_cached_roots() {
                        eprintln!(
                            "{} failed to refresh public roots ({}); using cached bundle from {} hours ago",
                            "Warning:".yellow().bold(),
                            e,
                            age.as_secs() / 3600
                        );
                        certs.extend(cached);
                        source = "embedded+cached";
                    } else {
                        eprintln!(
                            "{} failed to refresh public roots ({}); using embedded set",
                            "Warning:".yellow().bold(),
                            e
                        );
                    }
                }
            }
        }
        Self::from_certs(&certs, source)
    }

    fn from_certs(certs: &[X509], source: &'static str) -> Result<Self> {
        let mut builder = X509StoreBuilder::new().map_err(|e| anyhow::anyhow!("Failed to create trust store: {e}"))?;
        // Trust anchoring, not validity: a publicly trusted root remains
        // publicly trusted even if a cert in the chain is expired. dcert
        // reports expiry separately.
        builder
            .set_flags(X509VerifyFlags::NO_CHECK_TIME)
            .map_err(|e| anyhow::anyhow!("Failed to set store flags: {e}"))?;
        let mut fingerprints = HashSet::new();
        for cert in certs {
            // Duplicate roots (embedded + refreshed overlap) are expected;
            // ignore add errors so a single bad cert can't abort the store.
            let _ = builder.add_cert(cert.clone());
            if let Ok(fp) = cert.digest(MessageDigest::sha256()) {
                fingerprints.insert(fp.to_vec());
            }
        }
        Ok(Self {
            store: builder.build(),
            fingerprints,
            source,
        })
    }

    /// Whether the DER-encoded certificate is itself a recognized public root.
    pub fn is_public_root_der(&self, der: &[u8]) -> bool {
        X509::from_der(der)
            .ok()
            .and_then(|c| c.digest(MessageDigest::sha256()).ok())
            .map(|fp| self.fingerprints.contains(&fp.to_vec()))
            .unwrap_or(false)
    }
}

/// Load the embedded Mozilla/CCADB roots as OpenSSL certificates.
fn embedded_roots() -> Vec<X509> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|der| X509::from_der(der.as_ref()).ok())
        .collect()
}

/// Classify the trust of `chain_ders` (leaf first, then any intermediates /
/// root supplied). Offline by default; performs AIA resolution only when
/// `opts.resolve_issuers` is set and the offline verdict is inconclusive.
pub fn assess_root_trust(
    roots: &PublicRoots,
    chain_ders: &[Vec<u8>],
    opts: &TrustOpts,
    proxy: &ProxyConfig,
) -> RootTrustInfo {
    let mut info = RootTrustInfo {
        classification: RootTrustClass::Unknown,
        publicly_trusted: false,
        trust_anchor_subject: None,
        trust_anchor_sha256: None,
        anchor_present_in_chain: false,
        chain_completed_via_aia: false,
        private_backend_reachable: None,
        source: roots.source,
        detail: None,
    };

    if chain_ders.is_empty() {
        info.detail = Some("No certificates to assess.".to_string());
        return info;
    }

    let mut certs: Vec<X509> = match chain_ders.iter().map(|d| X509::from_der(d)).collect() {
        Ok(c) => c,
        Err(_) => {
            info.detail = Some("Certificate could not be parsed for trust assessment.".to_string());
            return info;
        }
    };

    classify(roots, &certs, &mut info);

    if opts.resolve_issuers
        && matches!(
            info.classification,
            RootTrustClass::Incomplete | RootTrustClass::PrivatePki
        )
    {
        let (completed, reachable) = resolve_issuers(&mut certs, opts, proxy);
        info.chain_completed_via_aia = completed;
        info.private_backend_reachable = reachable;
        // Re-assess: a fetched intermediate may now reach a public root, or we
        // may have retrieved the private root itself.
        classify(roots, &certs, &mut info);
    }

    info
}

/// Details of the root a chain anchors to, captured inside the verify closure.
struct AnchorInfo {
    subject: String,
    sha256: String,
    present_in_chain: bool,
}

/// Core offline classification of an in-memory chain.
fn classify(roots: &PublicRoots, certs: &[X509], info: &mut RootTrustInfo) {
    let leaf = &certs[0];

    let Ok(mut stack) = Stack::new() else {
        return;
    };
    for c in &certs[1..] {
        let _ = stack.push(c.clone());
    }

    // verify_cert against the public store; capture the anchoring root details.
    let verdict: std::result::Result<(bool, Option<AnchorInfo>), openssl::error::ErrorStack> = {
        let Ok(mut ctx) = X509StoreContext::new() else {
            return;
        };
        ctx.init(&roots.store, leaf, &stack, |c| {
            let ok = c.verify_cert()?;
            let mut anchor = None;
            if ok
                && let Some(chain) = c.chain()
                && let Some(root) = chain.iter().last()
            {
                anchor = Some(AnchorInfo {
                    subject: format_name(root.subject_name()),
                    sha256: fingerprint_hex(root),
                    present_in_chain: cert_in_chain(root, certs),
                });
            }
            Ok((ok, anchor))
        })
    };

    match verdict {
        Ok((true, anchor)) => {
            info.classification = RootTrustClass::PubliclyTrusted;
            info.publicly_trusted = true;
            if let Some(AnchorInfo {
                subject,
                sha256: fp,
                present_in_chain: present,
            }) = anchor
            {
                info.trust_anchor_subject = Some(subject);
                info.trust_anchor_sha256 = Some(fp);
                info.anchor_present_in_chain = present;
            }
            info.detail = Some("Chain anchors to a publicly trusted root CA (Mozilla/CCADB).".to_string());
        }
        _ => {
            info.publicly_trusted = false;
            let Some(top) = certs.last() else {
                return;
            };
            if is_self_signed(top) {
                info.trust_anchor_subject = Some(format_name(top.subject_name()));
                info.trust_anchor_sha256 = Some(fingerprint_hex(top));
                info.anchor_present_in_chain = true;
                if certs.len() == 1 {
                    info.classification = RootTrustClass::SelfSigned;
                    info.detail = Some("Single self-signed certificate — not issued by any CA.".to_string());
                } else {
                    info.classification = RootTrustClass::PrivatePki;
                    info.detail = Some(
                        "Chain terminates in a private self-signed root not in any public root program.".to_string(),
                    );
                }
            } else {
                info.classification = RootTrustClass::Incomplete;
                info.detail = Some(
                    "Chain does not reach a publicly trusted root and no self-signed root was presented \
                     (an issuer is missing). Re-run with --resolve-issuers to fetch it."
                        .to_string(),
                );
            }
        }
    }
}

/// Follow AIA "CA Issuers" URLs from the current top-of-chain certificate,
/// appending fetched issuers until a self-signed root is reached, no AIA URL
/// remains, or [`MAX_AIA_HOPS`] is hit. Returns whether the chain was extended
/// and whether a backend was reachable (`None` if never attempted).
fn resolve_issuers(certs: &mut Vec<X509>, opts: &TrustOpts, proxy: &ProxyConfig) -> (bool, Option<bool>) {
    let mut completed = false;
    let mut reachable: Option<bool> = None;

    for _ in 0..MAX_AIA_HOPS {
        let Some(top) = certs.last() else {
            break;
        };
        if is_self_signed(top) {
            break; // already at a root
        }
        let Ok(der) = top.to_der() else {
            break;
        };
        let urls = match X509Certificate::from_der(&der) {
            Ok((_, parsed)) => extract_ca_issuer_urls(&parsed),
            Err(_) => break,
        };
        if urls.is_empty() {
            break;
        }

        let mut fetched_this_hop = false;
        for url in urls {
            // We attempted a backend connection; record reachability.
            if reachable.is_none() {
                reachable = Some(false);
            }
            match fetch_issuer(&url, opts, proxy) {
                Ok(bytes) => {
                    reachable = Some(true);
                    if let Some(issuer) = parse_issuer_cert(&bytes) {
                        // Only a certificate whose key verifies the
                        // signature of the one below may join the chain;
                        // anything an endpoint serves otherwise is ignored.
                        if !issued_by(certs.last(), &issuer) {
                            debug_log!(
                                opts.debug,
                                "AIA certificate from {} did not sign the certificate below it; ignored",
                                url
                            );
                            continue;
                        }
                        // Guard against an endpoint returning a cert already in
                        // the chain (would loop forever).
                        if cert_in_chain(&issuer, certs) {
                            debug_log!(opts.debug, "AIA issuer already in chain; stopping");
                            break;
                        }
                        debug_log!(opts.debug, "Fetched issuer via AIA: {}", url);
                        certs.push(issuer);
                        completed = true;
                        fetched_this_hop = true;
                        break;
                    }
                }
                Err(e) => {
                    debug_log!(opts.debug, "AIA fetch failed ({}): {}", url, e);
                }
            }
        }
        if !fetched_this_hop {
            break;
        }
    }

    (completed, reachable)
}

/// Whether `issuer`'s public key verifies the signature on `child`.
fn issued_by(child: Option<&X509>, issuer: &X509) -> bool {
    let (Some(child), Ok(key)) = (child, issuer.public_key()) else {
        return false;
    };
    child.verify(&key).unwrap_or(false)
}

/// Extract AIA "CA Issuers" URLs (OID 1.3.6.1.5.5.7.48.2) from a certificate.
pub fn extract_ca_issuer_urls(cert: &X509Certificate<'_>) -> Vec<String> {
    crate::cert::aia_uris(cert, crate::cert::AiaMethod::CaIssuers)
}

/// Parse a fetched AIA payload into a certificate. Handles DER and PEM
/// encodings (the common `application/pkix-cert` forms).
fn parse_issuer_cert(bytes: &[u8]) -> Option<X509> {
    if let Ok(c) = X509::from_der(bytes) {
        return Some(c);
    }
    if let Ok(c) = X509::from_pem(bytes) {
        return Some(c);
    }
    None
}

/// Redirects followed when fetching an AIA issuer certificate.
const ISSUER_MAX_REDIRECTS: usize = 2;

/// Build a blocking HTTP client whose proxy behaviour mirrors dcert's
/// [`ProxyConfig`] and whose connect and read timeout is the short issuer
/// timeout.
fn http_client(proxy: &ProxyConfig, timeout: Duration, max_redirects: usize) -> Result<reqwest::blocking::Client> {
    crate::http::blocking_client(&crate::http::HttpClientOptions {
        timeout: Some(timeout),
        proxy: Some(proxy),
        // AIA endpoints occasionally redirect http to https; anything longer
        // is not a CA repository, and an unbounded chain would let a hostile
        // issuer URL walk the client around arbitrary hosts.
        max_redirects: Some(max_redirects),
        ..Default::default()
    })
}

/// Fetch an issuer certificate from an AIA "CA Issuers" URL.
///
/// Note: unlike the OCSP path, this intentionally does *not* block private /
/// internal IPs — private-PKI AIA endpoints legitimately live on internal
/// hosts, which is exactly the case `--resolve-issuers` exists to reach. It is
/// gated behind that explicit opt-in flag.
///
/// The destination policy (`DCERT_ALLOWED_TARGETS`, `DCERT_DENY_PRIVATE_TARGETS`,
/// set by the MCP server for its child) still applies, and while it
/// restricts anything redirects are not followed, since a redirect would
/// reach a host that was never checked.
fn fetch_issuer(url: &str, opts: &TrustOpts, proxy: &ProxyConfig) -> Result<Vec<u8>> {
    crate::netpolicy::enforce_url(url)?;
    let restricted = crate::netpolicy::cli_policy().map_or(true, |p| !p.is_open());
    let redirects = if restricted { 0 } else { ISSUER_MAX_REDIRECTS };
    let client = http_client(proxy, opts.issuer_timeout, redirects)?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| anyhow::anyhow!("request failed: {e}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }
    read_capped(resp, MAX_ISSUER_BYTES, "issuer response")
}

/// Read a response body without ever buffering more than `cap` bytes. The
/// declared `Content-Length` is checked first, then the stream is cut off
/// one byte past the cap so an oversized body is rejected before it lands
/// in memory.
fn read_capped(resp: reqwest::blocking::Response, cap: usize, what: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    if let Some(len) = resp.content_length()
        && len > cap as u64
    {
        anyhow::bail!("{what} too large ({len} bytes, limit {cap})");
    }
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    resp.take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("read failed: {e}"))?;
    if buf.len() > cap {
        anyhow::bail!("{what} too large (more than {cap} bytes)");
    }
    Ok(buf)
}

/// Fetch and parse the upstream Mozilla/CCADB PEM bundle, caching it best-effort.
fn refresh_public_roots(proxy: &ProxyConfig, timeout: Duration, debug: bool) -> Result<Vec<X509>> {
    let client = http_client(proxy, timeout, ISSUER_MAX_REDIRECTS)?;
    let resp = client
        .get(CCADB_BUNDLE_URL)
        .send()
        .map_err(|e| anyhow::anyhow!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pem = read_capped(resp, MAX_BUNDLE_BYTES, "CCADB bundle")?;

    let certs = X509::stack_from_pem(&pem).map_err(|e| anyhow::anyhow!("failed to parse CCADB bundle: {e}"))?;

    if let Some(path) = cache_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // `write_public_file` removes whatever sits at the path and creates
        // the file fresh, so a symlink planted there is replaced rather than
        // followed; the bundle is public data, so the umask mode is fine.
        match crate::convert::write_public_file(&path.to_string_lossy(), &pem) {
            Ok(()) => debug_log!(debug, "Cached refreshed public roots to {}", path.display()),
            Err(e) => debug_log!(debug, "Could not cache public roots at {}: {}", path.display(), e),
        }
    }

    Ok(certs)
}

/// Best-effort on-disk cache location for the refreshed bundle:
/// `$XDG_CACHE_HOME/dcert/public-roots.pem`, else
/// `$HOME/.cache/dcert/public-roots.pem`. `None` when neither variable is
/// set: the cache is then simply not used. There is deliberately no fallback
/// to the system temporary directory, which is shared between users and
/// would let anyone on the host plant a bundle that this user's chains are
/// then classified against.
fn cache_path() -> Option<std::path::PathBuf> {
    cache_path_from(
        std::env::var_os("XDG_CACHE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// [`cache_path`] with the environment passed in, for tests.
fn cache_path_from(
    xdg_cache_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<std::path::PathBuf> {
    let non_empty = |v: Option<&std::ffi::OsStr>| v.filter(|v| !v.is_empty()).map(std::path::PathBuf::from);
    let base = non_empty(xdg_cache_home).or_else(|| non_empty(home).map(|h| h.join(".cache")))?;
    Some(base.join("dcert").join("public-roots.pem"))
}

/// Load a previously cached bundle, returning the certificates and the age of
/// the cache file. Used when a refresh fails so an outage does not silently
/// downgrade trust classification to the embedded set.
fn read_cached_roots() -> Option<(Vec<X509>, Duration)> {
    read_cached_roots_at(&cache_path()?)
}

/// [`read_cached_roots`] for an explicit path.
///
/// The file feeds the trust store, so it is only accepted when it could not
/// have been written by another local user: it must be a regular file, not a
/// symlink, and on Unix it must be owned by the current user and not be
/// writable by group or others. On other platforms the ownership and mode
/// checks are not available and the file is accepted as found.
fn read_cached_roots_at(path: &std::path::Path) -> Option<(Vec<X509>, Duration)> {
    let link_meta = std::fs::symlink_metadata(path).ok()?;
    if link_meta.file_type().is_symlink() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    // Inspect the handle we actually read from, so a swap between the
    // metadata check and the read cannot slip a different file in.
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_BUNDLE_BYTES as u64 || !cache_file_is_trusted(&meta) {
        return None;
    }
    let age = meta.modified().ok().and_then(|m| m.elapsed().ok()).unwrap_or_default();
    let mut pem = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    {
        use std::io::Read;
        file.take(MAX_BUNDLE_BYTES as u64 + 1).read_to_end(&mut pem).ok()?;
    }
    if pem.len() > MAX_BUNDLE_BYTES {
        return None;
    }
    let certs = X509::stack_from_pem(&pem).ok()?;
    if certs.is_empty() {
        return None;
    }
    Some((certs, age))
}

/// Unix: the cache file must belong to the current user and must not be
/// writable by group or others (mode bits 0o022 clear).
#[cfg(unix)]
fn cache_file_is_trusted(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(uid) = current_uid() else {
        return false;
    };
    meta.uid() == uid && meta.mode() & 0o022 == 0
}

/// Windows and other platforms: no portable ownership or mode check, accept.
#[cfg(not(unix))]
fn cache_file_is_trusted(_meta: &std::fs::Metadata) -> bool {
    true
}

/// Effective uid of this process, read from the ownership of a file the
/// process creates itself: the standard library exposes no `geteuid`, and a
/// freshly created file is always owned by the creator's effective uid.
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    tempfile::tempfile().ok()?.metadata().ok().map(|m| m.uid())
}

// --- small helpers ---------------------------------------------------------

/// A certificate is self-signed if it verifies under its own public key.
fn is_self_signed(cert: &X509Ref) -> bool {
    cert.public_key()
        .ok()
        .and_then(|key| cert.verify(&key).ok())
        .unwrap_or(false)
}

/// Whether `cert` (by SHA-256) is present among `chain`.
fn cert_in_chain(cert: &X509Ref, chain: &[X509]) -> bool {
    let Ok(target) = cert.digest(MessageDigest::sha256()) else {
        return false;
    };
    chain
        .iter()
        .filter_map(|c| c.digest(MessageDigest::sha256()).ok())
        .any(|fp| fp.as_ref() == target.as_ref())
}

#[cfg(test)]
mod tests {

    #[test]
    fn an_aia_certificate_must_verify_the_child_signature() {
        let pki = crate::testutil::test_pki();
        assert!(
            issued_by(Some(&pki.rsa.cert), &pki.ca.cert),
            "the test CA signed the leaf"
        );
        assert!(
            !issued_by(Some(&pki.rsa.cert), &pki.ecdsa.cert),
            "a sibling leaf did not"
        );
        assert!(!issued_by(None, &pki.ca.cert));
    }
    use super::*;

    // Self-signed test certificate (CN=test.example.com).
    const VALID_PEM: &str = include_str!("../tests/data/valid.pem");
    // Multi-cert chain terminating in a private self-signed root.
    const CHAIN_PEM: &str = include_str!("../tests/data/test.pem");

    fn ders_from_pem(pem: &str) -> Vec<Vec<u8>> {
        pem::parse_many(pem)
            .unwrap()
            .into_iter()
            .filter(|b| b.tag() == "CERTIFICATE")
            .map(|b| b.contents().to_vec())
            .collect()
    }

    fn roots() -> PublicRoots {
        PublicRoots::from_certs(&embedded_roots(), "embedded").unwrap()
    }

    fn no_proxy() -> ProxyConfig {
        ProxyConfig {
            https_proxy: None,
            http_proxy: None,
            no_proxy: String::new(),
        }
    }

    fn offline_opts() -> TrustOpts {
        TrustOpts {
            resolve_issuers: false,
            issuer_timeout: Duration::from_secs(2),
            debug: false,
        }
    }

    #[test]
    fn embedded_store_is_populated() {
        // The Mozilla/CCADB set has well over a hundred roots.
        assert!(
            embedded_roots().len() > 100,
            "expected the embedded Mozilla/CCADB root set to be populated"
        );
    }

    #[test]
    fn empty_chain_is_unknown() {
        let info = assess_root_trust(&roots(), &[], &offline_opts(), &no_proxy());
        assert_eq!(info.classification, RootTrustClass::Unknown);
        assert!(!info.publicly_trusted);
    }

    #[test]
    fn self_signed_cert_is_self_signed() {
        let ders = ders_from_pem(VALID_PEM);
        let info = assess_root_trust(&roots(), &ders, &offline_opts(), &no_proxy());
        assert_eq!(info.classification, RootTrustClass::SelfSigned);
        assert!(!info.publicly_trusted);
        assert!(info.anchor_present_in_chain);
    }

    #[test]
    fn private_chain_is_private_pki() {
        let ders = ders_from_pem(CHAIN_PEM);
        let info = assess_root_trust(&roots(), &ders, &offline_opts(), &no_proxy());
        assert_eq!(info.classification, RootTrustClass::PrivatePki);
        assert!(!info.publicly_trusted);
    }

    #[test]
    fn embedded_root_is_recognized_private_cert_is_not() {
        let r = roots();
        let embedded = webpki_root_certs::TLS_SERVER_ROOT_CERTS[0].as_ref();
        assert!(
            r.is_public_root_der(embedded),
            "first embedded root should be recognized"
        );

        let private_der = &ders_from_pem(VALID_PEM)[0];
        assert!(
            !r.is_public_root_der(private_der),
            "self-signed test cert must not be a public root"
        );
    }

    #[test]
    fn resolve_issuers_off_does_no_network() {
        // With resolve_issuers=false, classification must not touch the network
        // even for an incomplete/private chain.
        let ders = ders_from_pem(CHAIN_PEM);
        let info = assess_root_trust(&roots(), &ders, &offline_opts(), &no_proxy());
        assert!(!info.chain_completed_via_aia);
        assert_eq!(info.private_backend_reachable, None);
    }

    // --- public root cache (M9) ---------------------------------------

    #[test]
    fn cache_path_has_no_temp_dir_fallback() {
        use std::ffi::OsStr;
        let xdg = OsStr::new("/xdg-cache");
        let home = OsStr::new("/home/alice");
        assert_eq!(
            cache_path_from(Some(xdg), Some(home)),
            Some(std::path::PathBuf::from("/xdg-cache/dcert/public-roots.pem"))
        );
        assert_eq!(
            cache_path_from(None, Some(home)),
            Some(std::path::PathBuf::from("/home/alice/.cache/dcert/public-roots.pem"))
        );
        // An empty variable counts as unset.
        assert_eq!(
            cache_path_from(Some(OsStr::new("")), Some(home)),
            Some(std::path::PathBuf::from("/home/alice/.cache/dcert/public-roots.pem"))
        );
        // Neither set: no cache at all, never the shared temp dir.
        assert_eq!(cache_path_from(None, None), None);
        assert_eq!(cache_path_from(Some(OsStr::new("")), Some(OsStr::new(""))), None);
    }

    /// PEM of the first embedded root, a valid bundle for cache tests.
    fn one_root_pem() -> Vec<u8> {
        embedded_roots()[0].to_pem().unwrap()
    }

    #[test]
    fn cached_roots_are_read_from_an_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public-roots.pem");
        std::fs::write(&path, one_root_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (certs, _age) = read_cached_roots_at(&path).expect("owner only cache file is accepted");
        assert_eq!(certs.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn cached_roots_ignore_a_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public-roots.pem");
        std::fs::write(&path, one_root_pem()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            read_cached_roots_at(&path).is_none(),
            "a cache file writable by group or others must be ignored"
        );
        // Group writable alone is enough to reject it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(read_cached_roots_at(&path).is_none());
        // Readable by others but writable only by the owner is fine.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_cached_roots_at(&path).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn cached_roots_ignore_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("planted.pem");
        std::fs::write(&target, one_root_pem()).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("public-roots.pem");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            read_cached_roots_at(&link).is_none(),
            "a symlinked cache file must be ignored"
        );
    }

    #[test]
    fn cached_roots_ignore_missing_empty_and_garbage_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_cached_roots_at(&dir.path().join("missing.pem")).is_none());
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        assert!(read_cached_roots_at(&empty).is_none());
        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, b"not a certificate").unwrap();
        assert!(read_cached_roots_at(&garbage).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn current_uid_is_known() {
        assert!(current_uid().is_some());
    }

    // --- embedded root set (webpki-root-certs 1.0.9) ---------------------

    fn embedded_root_subjects() -> Vec<String> {
        embedded_roots().iter().map(|c| format_name(c.subject_name())).collect()
    }

    fn has_root_cn(subjects: &[String], cn: &str) -> bool {
        let needle = format!("CN={cn}");
        subjects.iter().any(|s| s.split(", ").any(|part| part == needle))
    }

    #[test]
    fn embedded_root_set_contains_current_public_roots() {
        let subjects = embedded_root_subjects();
        for cn in [
            "ISRG Root X1",
            "ISRG Root X2",
            "GTS Root R1",
            "GTS Root R4",
            "DigiCert TLS RSA4096 Root G5",
            "DigiCert TLS ECC P384 Root G5",
            "Amazon Root CA 1",
            "USERTrust RSA Certification Authority",
            // Still trusted by Mozilla, hence embedded, although Chrome
            // distrusts certificates they issued after 2025-07-31. The
            // knowledge base entry tls.handshake.chrome-distrusted-root
            // relies on these being present.
            "HiPKI Root CA - G1",
            "NetLock Arany (Class Gold) Főtanúsítvány",
        ] {
            assert!(has_root_cn(&subjects, cn), "expected embedded root with CN={cn}");
        }
    }

    #[test]
    fn embedded_root_set_excludes_distrusted_roots() {
        let subjects = embedded_root_subjects();
        for cn in [
            // Removed from the Mozilla root store (distrusted for TLS) and so
            // from webpki-root-certs; the knowledge base explains chains that
            // still anchor on them.
            "Entrust Root Certification Authority - G2",
            "Entrust Root Certification Authority",
            "Entrust Root Certification Authority - EC1",
            // Retired by Google Trust Services.
            "GTS Root R2",
            // DigiCert G1 generation, removed by the root programs in 2026.
            "DigiCert Global Root CA",
            "DigiCert High Assurance EV Root CA",
            "DigiCert Assured ID Root CA",
        ] {
            assert!(!has_root_cn(&subjects, cn), "did not expect embedded root with CN={cn}");
        }
        assert!(
            !subjects.iter().any(|s| s.contains("O=Entrust")),
            "no Entrust root should remain in the embedded set"
        );
    }
}
