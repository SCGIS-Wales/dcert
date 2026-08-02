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
use openssl::x509::{X509, X509NameRef, X509Ref, X509StoreContext};
use std::collections::HashSet;
use std::time::Duration;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

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
                    eprintln!(
                        "{} failed to refresh public roots ({}); using embedded set",
                        "WARNING:".yellow().bold(),
                        e
                    );
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

    let mut stack = match Stack::new() {
        Ok(s) => s,
        Err(_) => return,
    };
    for c in &certs[1..] {
        let _ = stack.push(c.clone());
    }

    // verify_cert against the public store; capture the anchoring root details.
    let verdict: std::result::Result<(bool, Option<AnchorInfo>), openssl::error::ErrorStack> = {
        let mut ctx = match X509StoreContext::new() {
            Ok(c) => c,
            Err(_) => return,
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
            let top = certs.last().expect("chain is non-empty");
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
        let top = certs.last().expect("chain is non-empty");
        if is_self_signed(top) {
            break; // already at a root
        }
        let der = match top.to_der() {
            Ok(d) => d,
            Err(_) => break,
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

/// Extract AIA "CA Issuers" URLs (OID 1.3.6.1.5.5.7.48.2) from a certificate.
/// Sibling of [`crate::cert::extract_ocsp_url`].
pub fn extract_ca_issuer_urls(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut urls = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                if desc.access_method.to_id_string() == "1.3.6.1.5.5.7.48.2"
                    && let GeneralName::URI(uri) = &desc.access_location
                {
                    urls.push(uri.to_string());
                }
            }
        }
    }
    urls
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

/// Build a blocking HTTP client whose proxy behaviour mirrors dcert's
/// [`ProxyConfig`] (the same `http_proxy`/`https_proxy`/`no_proxy` env vars the
/// TLS path uses) and whose connect/read timeout is the short issuer timeout.
fn http_client(proxy: &ProxyConfig, timeout: Duration) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .user_agent(concat!("dcert/", env!("CARGO_PKG_VERSION")));

    let no_proxy = reqwest::NoProxy::from_string(&proxy.no_proxy);
    if let Some(p) = &proxy.https_proxy {
        builder = builder.proxy(
            reqwest::Proxy::https(p)
                .map_err(|e| anyhow::anyhow!("invalid https proxy '{p}': {e}"))?
                .no_proxy(no_proxy.clone()),
        );
    }
    if let Some(p) = &proxy.http_proxy {
        builder = builder.proxy(
            reqwest::Proxy::http(p)
                .map_err(|e| anyhow::anyhow!("invalid http proxy '{p}': {e}"))?
                .no_proxy(no_proxy),
        );
    }
    builder
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))
}

/// Fetch an issuer certificate from an AIA "CA Issuers" URL.
///
/// Note: unlike the OCSP path, this intentionally does *not* block private /
/// internal IPs — private-PKI AIA endpoints legitimately live on internal
/// hosts, which is exactly the case `--resolve-issuers` exists to reach. It is
/// gated behind that explicit opt-in flag.
fn fetch_issuer(url: &str, opts: &TrustOpts, proxy: &ProxyConfig) -> Result<Vec<u8>> {
    let client = http_client(proxy, opts.issuer_timeout)?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| anyhow::anyhow!("request failed: {e}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }
    let bytes = resp.bytes().map_err(|e| anyhow::anyhow!("read failed: {e}"))?;
    if bytes.len() > MAX_ISSUER_BYTES {
        anyhow::bail!("issuer response too large ({} bytes)", bytes.len());
    }
    Ok(bytes.to_vec())
}

/// Fetch and parse the upstream Mozilla/CCADB PEM bundle, caching it best-effort.
fn refresh_public_roots(proxy: &ProxyConfig, timeout: Duration, debug: bool) -> Result<Vec<X509>> {
    let client = http_client(proxy, timeout)?;
    let pem = client
        .get(CCADB_BUNDLE_URL)
        .send()
        .map_err(|e| anyhow::anyhow!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .bytes()
        .map_err(|e| anyhow::anyhow!("read failed: {e}"))?;

    if pem.len() > MAX_BUNDLE_BYTES {
        anyhow::bail!("CCADB bundle too large ({} bytes)", pem.len());
    }

    let certs = X509::stack_from_pem(&pem).map_err(|e| anyhow::anyhow!("failed to parse CCADB bundle: {e}"))?;

    if let Some(path) = cache_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&path, &pem).is_ok() {
            debug_log!(debug, "Cached refreshed public roots to {}", path.display());
        }
    }

    Ok(certs)
}

/// Best-effort on-disk cache location for the refreshed bundle.
fn cache_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    Some(base.join("dcert").join("public-roots.pem"))
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

/// Render an X.509 name as `CN=..., O=..., C=...`.
fn format_name(name: &X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let key = entry.object().nid().short_name().unwrap_or("?");
        if let Ok(value) = entry.data().to_string() {
            parts.push(format!("{}={}", key, value));
        }
    }
    parts.join(", ")
}

/// Colon-separated uppercase SHA-256 fingerprint (matches dcert's cert output).
fn fingerprint_hex(cert: &X509Ref) -> String {
    cert.digest(MessageDigest::sha256())
        .map(|d| d.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
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
}
