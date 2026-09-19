//! CloudFront and forward proxy diagnostics.
//!
//! A `dcert check` run captures evidence at every layer it reaches: the
//! proxy environment, the proxy `CONNECT` reply, the TLS handshake, the
//! negotiated session, the certificate chain and its trust anchor, and the
//! HTTP status, headers and body excerpt. This module scores that evidence
//! against a YAML knowledge base of failure signatures (`kb/diagnostics.yaml`,
//! embedded at build time and extendable at runtime with `--kb-file`) and
//! reports the most likely root cause per layer, earliest layer first.
//!
//! The engine is pure: it performs no I/O and never touches the network.

use anyhow::{Context, Result};
use regex_lite::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

use crate::cert::CertInfo;
use crate::proxy::{ProxyConfig, ProxyConnectFailed};
use crate::tls::{HttpHeader, TlsConnectionInfo};
use crate::trust::{RootTrustClass, RootTrustInfo};

/// The knowledge base compiled into the binary.
pub const BUILTIN_KB: &str = include_str!("../kb/diagnostics.yaml");

/// Entries below this confidence are not reported.
pub const MIN_CONFIDENCE: f32 = 0.45;

// ---------------------------------------------------------------------------
// Knowledge base schema
// ---------------------------------------------------------------------------

/// Where in the request path a failure is attributed. The order is the order
/// in which a probe traverses the path, and the order diagnoses are reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    LocalProxyEnv,
    ProxyConnect,
    TlsHandshake,
    ViewerMtls,
    Interception,
    EdgeHttp,
    OriginHttp,
}

impl Layer {
    pub fn label(self) -> &'static str {
        match self {
            Layer::LocalProxyEnv => "local proxy environment",
            Layer::ProxyConnect => "proxy CONNECT",
            Layer::TlsHandshake => "TLS handshake",
            Layer::ViewerMtls => "viewer mTLS",
            Layer::Interception => "TLS interception",
            Layer::EdgeHttp => "CloudFront edge",
            Layer::OriginHttp => "origin",
        }
    }
}

/// Broad grouping used for filtering and display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Cloudfront,
    Proxy,
    Tls,
    Mtls,
    Interception,
}

/// Root trust classes a signal can test for; mirrors [`RootTrustClass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RootClass {
    PubliclyTrusted,
    PrivatePki,
    SelfSigned,
    Incomplete,
    Unknown,
}

impl From<&RootTrustClass> for RootClass {
    fn from(c: &RootTrustClass) -> Self {
        match c {
            RootTrustClass::PubliclyTrusted => RootClass::PubliclyTrusted,
            RootTrustClass::PrivatePki => RootClass::PrivatePki,
            RootTrustClass::SelfSigned => RootClass::SelfSigned,
            RootTrustClass::Incomplete => RootClass::Incomplete,
            RootTrustClass::Unknown => RootClass::Unknown,
        }
    }
}

/// One observable condition. Regex patterns use the `regex-lite` syntax
/// (no look around); prefix with `(?i)` for case insensitive matching.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalKind {
    /// HTTP status code of the final response is one of `codes`.
    Status { codes: Vec<u16> },
    /// A response header named `name` matches `pattern`.
    Header { name: String, pattern: String },
    /// No response header named `name` is present.
    HeaderAbsent { name: String },
    /// The captured body excerpt matches `pattern`.
    Body { pattern: String },
    /// The connection error text matches `pattern` (TLS alerts, socket errors).
    Error { pattern: String },
    /// The proxy answered `CONNECT` with one of `codes`.
    ProxyStatus { codes: Vec<u16> },
    /// A header in the proxy's `CONNECT` reply matches `pattern`.
    ProxyHeader { name: String, pattern: String },
    /// Whether a forward proxy applies to this target.
    ProxyConfigured { value: bool },
    /// `HTTP_PROXY` is set while neither `HTTPS_PROXY` nor `ALL_PROXY` is.
    HttpsProxyMissingHttpSet,
    /// Any subject, issuer or trust anchor name in the chain matches `pattern`.
    ChainName { pattern: String },
    /// The chain's root trust classification.
    RootClass { is: RootClass },
    /// The target host is a public internet name (not an IP, not internal).
    PublicHostname,
    /// The target host matches `pattern`.
    TargetHost { pattern: String },
    /// Negotiated TLS version matches `pattern`.
    TlsVersion { pattern: String },
    /// Negotiated ALPN protocol matches `pattern`.
    Alpn { pattern: String },
    /// The server asked for a client certificate and the handshake aborted.
    ClientAuthRequired,
    /// A client certificate was supplied on the command line.
    ClientCertSupplied,
    /// `--sni` overrode the server name.
    SniOverridden,
    /// `--no-verify` was set.
    VerificationDisabled,
    /// The OpenSSL verify result text matches `pattern`.
    VerifyResult { pattern: String },
}

/// A weighted, optionally required, optionally negated signal.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Signal {
    #[serde(flatten)]
    pub kind: SignalKind,
    /// The entry cannot match unless this signal matches.
    #[serde(default)]
    pub required: bool,
    /// Contribution to the confidence score (default 1).
    #[serde(default = "default_signal_weight")]
    pub weight: f32,
    /// Invert the signal: it matches when the condition does not hold.
    #[serde(default)]
    pub negate: bool,
}

fn default_signal_weight() -> f32 {
    1.0
}

fn default_entry_weight() -> f32 {
    1.0
}

/// One failure signature with its explanation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Stable identifier, e.g. `cloudfront.edge.waf-blocked`.
    pub id: String,
    pub title: String,
    pub layer: Layer,
    pub category: Category,
    /// Maximum confidence when every signal matches (0 to 1).
    #[serde(default = "default_entry_weight")]
    pub weight: f32,
    pub signals: Vec<Signal>,
    pub root_cause: String,
    #[serde(default)]
    pub remediation: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    /// A catch all for its layer: reported only when no other entry in the
    /// same layer matched.
    #[serde(default)]
    pub fallback: bool,
}

/// The whole knowledge base file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeBase {
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl KnowledgeBase {
    /// Parse and validate the embedded knowledge base.
    pub fn builtin() -> Result<Self> {
        Self::parse(BUILTIN_KB).context("built in diagnostics knowledge base is invalid")
    }

    /// Parse and validate a YAML document.
    pub fn parse(yaml: &str) -> Result<Self> {
        let kb: Self = serde_yaml_ng::from_str(yaml).context("failed to parse diagnostics YAML")?;
        kb.validate()?;
        Ok(kb)
    }

    /// Load the built in base, then merge an optional operator file over it.
    /// An entry in the file with an existing id replaces the built in one.
    pub fn load(extra: Option<&Path>) -> Result<Self> {
        let mut kb = Self::builtin()?;
        if let Some(path) = extra {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read knowledge base file {}", path.display()))?;
            let other =
                Self::parse(&text).with_context(|| format!("invalid knowledge base file {}", path.display()))?;
            kb.merge(other);
        }
        Ok(kb)
    }

    /// Replace or append entries from `other`.
    pub fn merge(&mut self, other: Self) {
        for entry in other.entries {
            match self.entries.iter_mut().find(|e| e.id == entry.id) {
                Some(slot) => *slot = entry,
                None => self.entries.push(entry),
            }
        }
    }

    /// Structural validation: unique ids, compiling regexes, sane weights.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            anyhow::bail!("unsupported knowledge base version {}", self.version);
        }
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if entry.id.trim().is_empty() {
                anyhow::bail!("an entry has an empty id");
            }
            if !seen.insert(entry.id.as_str()) {
                anyhow::bail!("duplicate entry id '{}'", entry.id);
            }
            if !(0.0..=1.0).contains(&entry.weight) {
                anyhow::bail!("entry '{}': weight must be between 0 and 1", entry.id);
            }
            if entry.signals.is_empty() {
                anyhow::bail!("entry '{}': at least one signal is required", entry.id);
            }
            if entry.root_cause.trim().is_empty() {
                anyhow::bail!("entry '{}': root_cause is required", entry.id);
            }
            for signal in &entry.signals {
                if signal.weight <= 0.0 {
                    anyhow::bail!("entry '{}': signal weight must be positive", entry.id);
                }
                if let Some(p) = signal.kind.pattern() {
                    Regex::new(p).with_context(|| format!("entry '{}': invalid regex '{p}'", entry.id))?;
                }
                if let SignalKind::Status { codes } | SignalKind::ProxyStatus { codes } = &signal.kind
                    && codes.is_empty()
                {
                    anyhow::bail!("entry '{}': status signal needs at least one code", entry.id);
                }
            }
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// JSON schema for the YAML file, for editor validation.
    pub fn json_schema() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(KnowledgeBase)).unwrap_or_default()
    }
}

impl SignalKind {
    fn pattern(&self) -> Option<&str> {
        match self {
            SignalKind::Header { pattern, .. }
            | SignalKind::Body { pattern }
            | SignalKind::Error { pattern }
            | SignalKind::ProxyHeader { pattern, .. }
            | SignalKind::ChainName { pattern }
            | SignalKind::TargetHost { pattern }
            | SignalKind::TlsVersion { pattern }
            | SignalKind::Alpn { pattern }
            | SignalKind::VerifyResult { pattern } => Some(pattern),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// Facts about the probe that do not come from the response itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProbeContext<'a> {
    pub proxy: Option<&'a ProxyConfig>,
    pub client_cert_supplied: bool,
    pub sni_overridden: bool,
}

/// Everything the engine can test. Built from a successful probe or from
/// the error of a failed one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Evidence {
    pub target_host: String,
    pub error: Option<String>,
    pub proxy_configured: bool,
    pub https_proxy_missing_http_set: bool,
    pub proxy_status: Option<u16>,
    pub proxy_headers: Vec<HttpHeader>,
    pub http_status: Option<u16>,
    pub http_headers: Vec<HttpHeader>,
    pub http_body: Option<String>,
    pub tls_version: Option<String>,
    pub alpn: Option<String>,
    pub verify_result: Option<String>,
    pub chain_errors: Vec<String>,
    pub client_auth_required: bool,
    pub client_cert_supplied: bool,
    pub sni_overridden: bool,
    pub verification_disabled: bool,
    /// Subjects, issuers and the trust anchor name, for vendor matching.
    pub chain_names: Vec<String>,
    pub root_class: Option<RootClass>,
}

impl Evidence {
    fn base(target: &str, ctx: &ProbeContext<'_>) -> Self {
        let host = target_host(target);
        let proxy_configured = ctx
            .proxy
            .map(|p| p.get_proxy_url("https").is_some() && !p.should_bypass(&host))
            .unwrap_or(false);
        Self {
            target_host: host,
            proxy_configured,
            https_proxy_missing_http_set: https_proxy_missing_http_set(),
            client_cert_supplied: ctx.client_cert_supplied,
            sni_overridden: ctx.sni_overridden,
            ..Default::default()
        }
    }

    /// Evidence from a probe that produced a result.
    pub fn from_result(
        target: &str,
        ctx: &ProbeContext<'_>,
        conn: Option<&TlsConnectionInfo>,
        infos: &[CertInfo],
        root_trust: Option<&RootTrustInfo>,
    ) -> Self {
        let mut ev = Self::base(target, ctx);
        if let Some(c) = conn {
            ev.http_status = (c.http_response_code > 0).then_some(c.http_response_code);
            ev.http_headers = c.http_headers.clone();
            ev.http_body = c.http_body_excerpt.clone();
            ev.tls_version = Some(c.tls_version.clone());
            ev.alpn = c.negotiated_protocol.clone();
            ev.verify_result = c.verify_result.clone();
            ev.chain_errors = c.chain_validation_errors.clone();
            ev.client_auth_required = c.client_auth_required;
            ev.verification_disabled = c.verification_disabled;
        }
        for info in infos {
            ev.chain_names.push(info.subject.clone());
            ev.chain_names.push(info.issuer.clone());
        }
        if let Some(rt) = root_trust {
            ev.root_class = Some(RootClass::from(&rt.classification));
            if let Some(anchor) = &rt.trust_anchor_subject {
                ev.chain_names.push(anchor.clone());
            }
        }
        ev
    }

    /// Evidence from a probe that failed before producing a result.
    pub fn from_error(target: &str, ctx: &ProbeContext<'_>, err: &anyhow::Error) -> Self {
        let mut ev = Self::base(target, ctx);
        ev.error = Some(format!("{err:#}"));
        if let Some(p) = err.downcast_ref::<ProxyConnectFailed>() {
            ev.proxy_status = Some(p.status);
            ev.proxy_headers = p.headers.clone();
        }
        let text = ev.error.as_deref().unwrap_or("");
        ev.client_auth_required = crate::tls::is_client_auth_required(text);
        ev
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.http_headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    fn proxy_header(&self, name: &str) -> Option<&str> {
        self.proxy_headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
}

/// Extract the host from a target string (`https://host:port/path`, bare
/// `host:port`, or a file path which yields an empty host).
pub fn target_host(target: &str) -> String {
    if let Ok(url) = url::Url::parse(target)
        && let Some(h) = url.host_str()
    {
        return h.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    }
    let bare = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
    if bare.contains('/') || bare.contains('\\') {
        return String::new();
    }
    bare.to_ascii_lowercase()
}

/// `true` for names that belong to the public internet rather than a LAN.
pub fn is_public_hostname(host: &str) -> bool {
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return false;
    }
    const PRIVATE_SUFFIXES: [&str; 12] = [
        ".local",
        ".localhost",
        ".internal",
        ".intranet",
        ".lan",
        ".corp",
        ".home",
        ".home.arpa",
        ".test",
        ".invalid",
        ".example",
        ".private",
    ];
    !PRIVATE_SUFFIXES.iter().any(|s| host.ends_with(s))
}

fn https_proxy_missing_http_set() -> bool {
    let set = |n: &str| std::env::var(n).map(|v| !v.is_empty()).unwrap_or(false);
    (set("HTTP_PROXY") || set("http_proxy"))
        && !(set("HTTPS_PROXY") || set("https_proxy") || set("ALL_PROXY") || set("all_proxy"))
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// One reported finding.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Diagnosis {
    pub id: String,
    pub title: String,
    pub layer: Layer,
    pub category: Category,
    /// 0 to 1.
    pub confidence: f32,
    pub root_cause: String,
    /// Human readable list of the signals that matched.
    pub evidence: Vec<String>,
    pub remediation: Vec<String>,
    pub references: Vec<String>,
}

/// Result of a diagnosis pass.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiagnosisReport {
    /// Findings ordered earliest layer first, then by confidence.
    pub findings: Vec<Diagnosis>,
    /// `true` when at least one finding matched on the body excerpt, so the
    /// excerpt is worth showing.
    pub body_matched: bool,
}

/// Score every entry against the evidence.
pub fn diagnose(kb: &KnowledgeBase, ev: &Evidence) -> DiagnosisReport {
    let mut report = DiagnosisReport::default();
    let mut fallbacks: Vec<bool> = Vec::new();
    let mut body_hits: Vec<bool> = Vec::new();
    for entry in &kb.entries {
        let mut matched_weight = 0.0f32;
        let mut total_weight = 0.0f32;
        let mut evidence = Vec::new();
        let mut required_failed = false;
        let mut body_hit = false;
        for signal in &entry.signals {
            total_weight += signal.weight;
            let (hit, description) = evaluate(&signal.kind, ev);
            let hit = hit != signal.negate;
            if hit {
                matched_weight += signal.weight;
                if let Some(d) = description
                    && !signal.negate
                {
                    evidence.push(d);
                }
                if matches!(signal.kind, SignalKind::Body { .. }) && !signal.negate {
                    body_hit = true;
                }
            } else if signal.required {
                required_failed = true;
                break;
            }
        }
        if required_failed || total_weight <= 0.0 {
            continue;
        }
        let confidence = entry.weight * (matched_weight / total_weight);
        if confidence < MIN_CONFIDENCE {
            continue;
        }
        fallbacks.push(entry.fallback);
        body_hits.push(body_hit);
        report.findings.push(Diagnosis {
            id: entry.id.clone(),
            title: entry.title.clone(),
            layer: entry.layer,
            category: entry.category,
            confidence: (confidence * 100.0).round() / 100.0,
            root_cause: entry.root_cause.trim().to_string(),
            evidence,
            remediation: entry.remediation.clone(),
            references: entry.references.clone(),
        });
    }
    // Drop layer fallbacks that a specific entry in the same layer superseded.
    let specific_layers: BTreeSet<Layer> = report
        .findings
        .iter()
        .zip(&fallbacks)
        .filter(|(_, fb)| !**fb)
        .map(|(d, _)| d.layer)
        .collect();
    let mut keep = fallbacks.iter().map(|fb| !*fb).collect::<Vec<_>>();
    for (i, d) in report.findings.iter().enumerate() {
        if fallbacks[i] && !specific_layers.contains(&d.layer) {
            keep[i] = true;
        }
    }
    let mut idx = 0;
    report.findings.retain(|_| {
        let k = keep[idx];
        idx += 1;
        k
    });
    // The body excerpt is kept only when a *surviving* finding matched on it.
    // Counting a suppressed fallback here would print the excerpt with nothing
    // left in the report that explains why it is there.
    report.body_matched = keep.iter().zip(&body_hits).any(|(kept, hit)| *kept && *hit);
    report.findings.sort_by(|a, b| {
        a.layer
            .cmp(&b.layer)
            .then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.id.cmp(&b.id))
    });
    report
}

fn re(pattern: &str) -> Option<Regex> {
    // Patterns were validated when the base was loaded; a failure here can
    // only come from an unvalidated in memory entry and is treated as no match.
    Regex::new(pattern).ok()
}

fn matches_pattern(pattern: &str, value: Option<&str>) -> bool {
    match (re(pattern), value) {
        (Some(r), Some(v)) => r.is_match(v),
        _ => false,
    }
}

fn short(value: &str) -> String {
    let one_line: String = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() > 120 {
        let cut: String = one_line.chars().take(117).collect();
        format!("{cut}...")
    } else {
        one_line
    }
}

/// Evaluate one signal. Returns whether it holds and, if so, a description.
fn evaluate(kind: &SignalKind, ev: &Evidence) -> (bool, Option<String>) {
    match kind {
        SignalKind::Status { codes } => match ev.http_status {
            Some(s) if codes.contains(&s) => (true, Some(format!("HTTP status {s}"))),
            _ => (false, None),
        },
        SignalKind::Header { name, pattern } => match ev.header(name) {
            Some(v) if matches_pattern(pattern, Some(v)) => (true, Some(format!("header {name}: {}", short(v)))),
            _ => (false, None),
        },
        SignalKind::HeaderAbsent { name } => (ev.header(name).is_none(), None),
        SignalKind::Body { pattern } => {
            let hit = matches_pattern(pattern, ev.http_body.as_deref());
            let desc = hit.then(|| {
                let excerpt = re(pattern)
                    .and_then(|r| {
                        r.find(ev.http_body.as_deref().unwrap_or(""))
                            .map(|m| m.as_str().to_string())
                    })
                    .unwrap_or_default();
                format!("body contains \"{}\"", short(&excerpt))
            });
            (hit, desc)
        }
        SignalKind::Error { pattern } => {
            let hit = matches_pattern(pattern, ev.error.as_deref());
            (
                hit,
                hit.then(|| format!("error: {}", short(ev.error.as_deref().unwrap_or("")))),
            )
        }
        SignalKind::ProxyStatus { codes } => match ev.proxy_status {
            Some(s) if codes.contains(&s) => (true, Some(format!("proxy CONNECT answered {s}"))),
            _ => (false, None),
        },
        SignalKind::ProxyHeader { name, pattern } => match ev.proxy_header(name) {
            Some(v) if matches_pattern(pattern, Some(v)) => (true, Some(format!("proxy header {name}: {}", short(v)))),
            _ => (false, None),
        },
        SignalKind::ProxyConfigured { value } => (
            ev.proxy_configured == *value,
            (ev.proxy_configured == *value).then(|| {
                if *value {
                    "a forward proxy applies to this target".to_string()
                } else {
                    "no forward proxy applies to this target".to_string()
                }
            }),
        ),
        SignalKind::HttpsProxyMissingHttpSet => (
            ev.https_proxy_missing_http_set,
            ev.https_proxy_missing_http_set
                .then(|| "HTTP_PROXY is set but HTTPS_PROXY and ALL_PROXY are not".to_string()),
        ),
        SignalKind::ChainName { pattern } => {
            let hit = ev.chain_names.iter().find(|n| matches_pattern(pattern, Some(n)));
            (hit.is_some(), hit.map(|n| format!("chain name: {}", short(n))))
        }
        SignalKind::RootClass { is } => {
            let hit = ev.root_class == Some(*is);
            (hit, hit.then(|| format!("root trust: {}", serde_variant_name(is))))
        }
        SignalKind::PublicHostname => {
            let hit = is_public_hostname(&ev.target_host);
            (hit, hit.then(|| format!("public hostname {}", ev.target_host)))
        }
        SignalKind::TargetHost { pattern } => {
            let hit = matches_pattern(pattern, Some(&ev.target_host));
            (hit, hit.then(|| format!("target host {}", ev.target_host)))
        }
        SignalKind::TlsVersion { pattern } => {
            let hit = matches_pattern(pattern, ev.tls_version.as_deref());
            (
                hit,
                hit.then(|| format!("TLS version {}", ev.tls_version.as_deref().unwrap_or(""))),
            )
        }
        SignalKind::Alpn { pattern } => {
            let hit = matches_pattern(pattern, ev.alpn.as_deref());
            (hit, hit.then(|| format!("ALPN {}", ev.alpn.as_deref().unwrap_or(""))))
        }
        SignalKind::ClientAuthRequired => (
            ev.client_auth_required,
            ev.client_auth_required
                .then(|| "server requested a client certificate".to_string()),
        ),
        SignalKind::ClientCertSupplied => (
            ev.client_cert_supplied,
            ev.client_cert_supplied
                .then(|| "a client certificate was supplied".to_string()),
        ),
        SignalKind::SniOverridden => (
            ev.sni_overridden,
            ev.sni_overridden.then(|| "SNI was overridden with --sni".to_string()),
        ),
        SignalKind::VerificationDisabled => (
            ev.verification_disabled,
            ev.verification_disabled
                .then(|| "certificate verification was disabled".to_string()),
        ),
        SignalKind::VerifyResult { pattern } => {
            let hit = matches_pattern(pattern, ev.verify_result.as_deref());
            (
                hit,
                hit.then(|| format!("verify result: {}", ev.verify_result.as_deref().unwrap_or(""))),
            )
        }
    }
}

fn serde_variant_name(c: &RootClass) -> &'static str {
    match c {
        RootClass::PubliclyTrusted => "publicly_trusted",
        RootClass::PrivatePki => "private_pki",
        RootClass::SelfSigned => "self_signed",
        RootClass::Incomplete => "incomplete",
        RootClass::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> HttpHeader {
        HttpHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn cloudfront_page(status: u16, sentence: &str) -> Evidence {
        Evidence {
            target_host: "www.example.com".to_string(),
            http_status: Some(status),
            http_headers: vec![
                header("server", "CloudFront"),
                header("x-cache", "Error from cloudfront"),
                header("via", "1.1 abc.cloudfront.net (CloudFront)"),
                header(
                    "x-amz-cf-id",
                    "gcnHsvlAfKdvMxW7RauXeFH_J3aCxf9Sxw13X_KUle3-dbH776K1pw==",
                ),
            ],
            http_body: Some(format!(
                "<html><h1>ERROR: The request could not be satisfied</h1><p>{sentence}</p>\
                 Generated by cloudfront (CloudFront) Request ID: abc</html>"
            )),
            ..Default::default()
        }
    }

    fn kb() -> KnowledgeBase {
        KnowledgeBase::builtin().expect("built in kb parses")
    }

    fn primary(ev: &Evidence) -> Diagnosis {
        let report = diagnose(&kb(), ev);
        report.findings.into_iter().next().expect("at least one finding")
    }

    #[test]
    fn builtin_kb_is_valid_and_non_trivial() {
        let kb = kb();
        assert!(kb.entries.len() >= 30, "expected a substantial catalogue");
        for entry in &kb.entries {
            assert!(!entry.remediation.is_empty(), "{} has no remediation", entry.id);
            assert!(!entry.references.is_empty(), "{} has no references", entry.id);
        }
    }

    #[test]
    fn schema_file_is_current() {
        let expected = serde_json::to_string_pretty(&KnowledgeBase::json_schema()).unwrap();
        let on_disk = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/kb/diagnostics.schema.json"))
            .unwrap_or_default();
        assert_eq!(
            on_disk.trim(),
            expected.trim(),
            "kb/diagnostics.schema.json is stale; run `dcert kb schema > kb/diagnostics.schema.json`"
        );
    }

    #[test]
    fn rejects_duplicate_ids_and_bad_regex() {
        let dup = "version: 1\nentries:\n  - {id: a, title: t, layer: edge_http, category: cloudfront, signals: [{type: status, codes: [500]}], root_cause: x}\n  - {id: a, title: t, layer: edge_http, category: cloudfront, signals: [{type: status, codes: [500]}], root_cause: x}\n";
        assert!(KnowledgeBase::parse(dup).unwrap_err().to_string().contains("duplicate"));
        let bad = "version: 1\nentries:\n  - {id: a, title: t, layer: edge_http, category: cloudfront, signals: [{type: body, pattern: '('}], root_cause: x}\n";
        assert!(
            KnowledgeBase::parse(bad)
                .unwrap_err()
                .to_string()
                .contains("invalid regex")
        );
        let unknown = "version: 1\nentries:\n  - {id: a, title: t, layer: edge_http, category: cloudfront, bogus: 1, signals: [{type: status, codes: [500]}], root_cause: x}\n";
        assert!(KnowledgeBase::parse(unknown).is_err());
    }

    #[test]
    fn merge_replaces_by_id() {
        let mut base = kb();
        let before = base.entries.len();
        let extra = KnowledgeBase::parse(
            "version: 1\nentries:\n  - {id: cloudfront.edge.waf-blocked, title: Custom, layer: edge_http, category: cloudfront, signals: [{type: status, codes: [403]}], root_cause: custom}\n  - {id: org.new, title: New, layer: origin_http, category: cloudfront, signals: [{type: status, codes: [418]}], root_cause: teapot}\n",
        )
        .unwrap();
        base.merge(extra);
        assert_eq!(base.entries.len(), before + 1);
        assert_eq!(base.get("cloudfront.edge.waf-blocked").unwrap().title, "Custom");
    }

    #[test]
    fn waf_block_is_identified() {
        let d = primary(&cloudfront_page(403, "Request blocked."));
        assert_eq!(d.id, "cloudfront.edge.waf-blocked");
        assert!(d.confidence > 0.9);
        assert!(d.evidence.iter().any(|e| e.contains("Request blocked")));
    }

    #[test]
    fn cname_not_configured_is_identified() {
        let d = primary(&cloudfront_page(
            403,
            "Bad request. We can't connect to the server for this app or website at this time.",
        ));
        assert_eq!(d.id, "cloudfront.edge.cname-not-configured");
    }

    #[test]
    fn geo_restriction_is_identified() {
        let d = primary(&cloudfront_page(
            403,
            "The Amazon CloudFront distribution is configured to block access from your country.",
        ));
        assert_eq!(d.id, "cloudfront.edge.geo-restricted");
    }

    #[test]
    fn origin_dns_failure_is_identified() {
        let d = primary(&cloudfront_page(
            502,
            "CloudFront wasn't able to resolve the origin domain name.",
        ));
        assert_eq!(d.id, "cloudfront.edge.origin-dns");
    }

    #[test]
    fn origin_tls_failure_is_identified() {
        let d = primary(&cloudfront_page(
            502,
            "CloudFront attempted to establish a connection with the origin, but either the attempt failed or the origin closed the connection.",
        ));
        assert_eq!(d.id, "cloudfront.edge.origin-tls-failure");
        assert!(d.remediation.iter().any(|r| r.contains("origin mTLS")));
    }

    #[test]
    fn origin_timeout_is_identified() {
        let d = primary(&cloudfront_page(
            504,
            "CloudFront wasn't able to connect to the origin.",
        ));
        assert_eq!(d.id, "cloudfront.edge.origin-timeout");
    }

    #[test]
    fn lambda_edge_and_function_errors_are_distinguished() {
        let d = primary(&cloudfront_page(
            503,
            "The Lambda function associated with the CloudFront distribution is invalid or doesn't have the required permissions.",
        ));
        assert_eq!(d.id, "cloudfront.edge.lambda-edge-invalid");
        let d = primary(&cloudfront_page(
            503,
            "The CloudFront function associated with the CloudFront distribution is invalid or doesn't have the required permissions.",
        ));
        assert_eq!(d.id, "cloudfront.edge.function-invalid");
    }

    #[test]
    fn unknown_edge_sentence_falls_back_to_generic_page() {
        let d = primary(&cloudfront_page(500, "Something new."));
        assert_eq!(d.id, "cloudfront.edge.generic-error-page");
    }

    #[test]
    fn generic_page_is_suppressed_when_a_specific_entry_matches() {
        let report = diagnose(&kb(), &cloudfront_page(403, "Request blocked."));
        assert!(
            !report
                .findings
                .iter()
                .any(|d| d.id == "cloudfront.edge.generic-error-page"),
            "{:?}",
            report.findings.iter().map(|d| &d.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn s3_access_denied_is_attributed_to_the_origin() {
        let mut ev = cloudfront_page(403, "");
        ev.http_headers = vec![
            header("server", "AmazonS3"),
            header("x-cache", "Error from cloudfront"),
            header("via", "1.1 abc.cloudfront.net (CloudFront)"),
        ];
        ev.http_body = Some("<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>".to_string());
        let d = primary(&ev);
        assert_eq!(d.id, "cloudfront.origin.s3-access-denied");
        assert_eq!(d.layer, Layer::OriginHttp);
    }

    #[test]
    fn origin_error_passed_through_is_flagged_as_origin() {
        let ev = Evidence {
            target_host: "api.example.com".to_string(),
            http_status: Some(500),
            http_headers: vec![
                header("server", "nginx"),
                header("via", "1.1 abc.cloudfront.net (CloudFront)"),
                header("x-cache", "Miss from cloudfront"),
            ],
            http_body: Some("internal error".to_string()),
            ..Default::default()
        };
        let d = primary(&ev);
        assert_eq!(d.id, "cloudfront.origin.error-forwarded");
    }

    #[test]
    fn healthy_cloudfront_response_is_informational_only() {
        let ev = Evidence {
            target_host: "www.example.com".to_string(),
            http_status: Some(200),
            http_headers: vec![
                header("via", "1.1 abc.cloudfront.net (CloudFront)"),
                header("x-cache", "Hit from cloudfront"),
                header("x-amz-cf-pop", "LHR62-P1"),
            ],
            ..Default::default()
        };
        let report = diagnose(&kb(), &ev);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].id, "cloudfront.info.served-by-cloudfront");
    }

    #[test]
    fn proxy_407_is_attributed_to_the_proxy_layer() {
        let ev = Evidence {
            target_host: "www.example.com".to_string(),
            error: Some("Proxy CONNECT failed: HTTP/1.1 407 Proxy Authentication Required".to_string()),
            proxy_configured: true,
            proxy_status: Some(407),
            proxy_headers: vec![header("proxy-authenticate", "Basic realm=\"corp\"")],
            ..Default::default()
        };
        let d = primary(&ev);
        assert_eq!(d.id, "proxy.connect.407-auth-required");
        assert_eq!(d.layer, Layer::ProxyConnect);
    }

    #[test]
    fn squid_upstream_failure_is_identified() {
        let ev = Evidence {
            target_host: "www.example.com".to_string(),
            error: Some("Proxy CONNECT failed: HTTP/1.1 503 Service Unavailable".to_string()),
            proxy_configured: true,
            proxy_status: Some(503),
            proxy_headers: vec![header("x-squid-error", "ERR_DNS_FAIL 0"), header("via", "1.1 squid")],
            ..Default::default()
        };
        let d = primary(&ev);
        assert_eq!(d.id, "proxy.connect.5xx-upstream");
        assert!(d.evidence.iter().any(|e| e.contains("ERR_DNS_FAIL")));
    }

    #[test]
    fn http_proxy_only_environment_is_flagged() {
        let ev = Evidence {
            target_host: "www.example.com".to_string(),
            error: Some("Failed to connect: connection timed out".to_string()),
            https_proxy_missing_http_set: true,
            ..Default::default()
        };
        let d = primary(&ev);
        assert_eq!(d.id, "proxy.env.https-without-https-proxy");
        assert_eq!(d.layer, Layer::LocalProxyEnv);
    }

    #[test]
    fn viewer_mtls_required_without_cert() {
        let ev = Evidence {
            target_host: "api.example.com".to_string(),
            error: Some("TLS handshake failed: tlsv13 alert certificate required".to_string()),
            client_auth_required: true,
            chain_names: vec!["CN=api.example.com".to_string(), "CN=Amazon RSA 2048 M02".to_string()],
            ..Default::default()
        };
        let d = primary(&ev);
        assert_eq!(d.id, "mtls.viewer.certificate-required");
        assert!(d.confidence > 0.9);
    }

    #[test]
    fn viewer_mtls_unknown_ca_with_cert() {
        let ev = Evidence {
            target_host: "api.example.com".to_string(),
            error: Some("TLS handshake failed: tlsv1 alert unknown ca".to_string()),
            client_cert_supplied: true,
            ..Default::default()
        };
        let d = primary(&ev);
        assert_eq!(d.id, "mtls.viewer.unknown-ca");
    }

    #[test]
    fn expired_client_cert_is_identified() {
        let ev = Evidence {
            target_host: "api.example.com".to_string(),
            error: Some("TLS handshake failed: sslv3 alert certificate expired".to_string()),
            client_cert_supplied: true,
            ..Default::default()
        };
        assert_eq!(primary(&ev).id, "mtls.viewer.certificate-expired");
    }

    #[test]
    fn interception_vendor_is_identified() {
        let ev = Evidence {
            target_host: "www.example.com".to_string(),
            http_status: Some(200),
            chain_names: vec![
                "CN=www.example.com".to_string(),
                "CN=Zscaler Intermediate Root CA (zscalerthree.net)".to_string(),
                "CN=Zscaler Root CA, O=Zscaler Inc.".to_string(),
            ],
            root_class: Some(RootClass::PrivatePki),
            ..Default::default()
        };
        let d = primary(&ev);
        assert_eq!(d.id, "interception.vendor-ca");
        assert_eq!(d.layer, Layer::Interception);
    }

    #[test]
    fn private_root_on_public_host_is_suspicious() {
        let ev = Evidence {
            target_host: "www.example.com".to_string(),
            http_status: Some(200),
            chain_names: vec![
                "CN=www.example.com".to_string(),
                "CN=Contoso Corp Issuing CA".to_string(),
            ],
            root_class: Some(RootClass::PrivatePki),
            ..Default::default()
        };
        let d = primary(&ev);
        assert_eq!(d.id, "interception.private-root-public-host");
    }

    #[test]
    fn private_root_on_internal_host_is_normal() {
        let ev = Evidence {
            target_host: "vault.corp".to_string(),
            http_status: Some(200),
            chain_names: vec!["CN=vault.corp".to_string(), "CN=Contoso Corp Issuing CA".to_string()],
            root_class: Some(RootClass::PrivatePki),
            ..Default::default()
        };
        assert!(diagnose(&kb(), &ev).findings.is_empty());
    }

    #[test]
    fn default_cloudfront_certificate_for_custom_host() {
        let ev = Evidence {
            target_host: "www.example.com".to_string(),
            http_status: Some(403),
            verify_result: Some("hostname mismatch".to_string()),
            chain_names: vec!["CN=*.cloudfront.net".to_string(), "CN=Amazon RSA 2048 M02".to_string()],
            ..Default::default()
        };
        let d = primary(&ev);
        assert_eq!(d.id, "tls.handshake.default-cloudfront-cert");
    }

    #[test]
    fn protocol_version_failure() {
        let ev = Evidence {
            target_host: "legacy.example.com".to_string(),
            error: Some("TLS handshake failed: tlsv1 alert protocol version".to_string()),
            ..Default::default()
        };
        assert_eq!(primary(&ev).id, "tls.handshake.protocol-version");
    }

    #[test]
    fn body_match_marks_report() {
        let report = diagnose(&kb(), &cloudfront_page(403, "Request blocked."));
        assert!(report.body_matched);
    }

    #[test]
    fn a_suppressed_fallback_does_not_mark_the_body_as_matched() {
        // One fallback entry that matches on the body, and one specific entry
        // in the same layer that does not. The fallback is dropped, so nothing
        // left in the report explains the body excerpt and it must not be
        // flagged as matched.
        let kb = KnowledgeBase {
            version: 1,
            entries: vec![
                Entry {
                    id: "edge.fallback".to_string(),
                    title: "Generic edge page".to_string(),
                    layer: Layer::EdgeHttp,
                    category: Category::Cloudfront,
                    weight: 1.0,
                    signals: vec![Signal {
                        kind: SignalKind::Body {
                            pattern: "generated by cloudfront".to_string(),
                        },
                        required: true,
                        weight: 1.0,
                        negate: false,
                    }],
                    root_cause: "An edge error page was returned.".to_string(),
                    remediation: vec!["Check the origin.".to_string()],
                    references: vec![],
                    fallback: true,
                },
                Entry {
                    id: "edge.specific".to_string(),
                    title: "Specific edge failure".to_string(),
                    layer: Layer::EdgeHttp,
                    category: Category::Cloudfront,
                    weight: 1.0,
                    signals: vec![Signal {
                        kind: SignalKind::Status { codes: vec![502] },
                        required: true,
                        weight: 1.0,
                        negate: false,
                    }],
                    root_cause: "The origin refused the connection.".to_string(),
                    remediation: vec!["Check the origin listener.".to_string()],
                    references: vec![],
                    fallback: false,
                },
            ],
        };
        let ev = Evidence {
            target_host: "www.example.com".to_string(),
            http_status: Some(502),
            http_body: Some("Generated by cloudfront".to_string()),
            ..Default::default()
        };

        let report = diagnose(&kb, &ev);
        assert_eq!(report.findings.len(), 1, "the fallback must be suppressed");
        assert_eq!(report.findings[0].id, "edge.specific");
        assert!(
            !report.body_matched,
            "no surviving finding matched on the body, so the excerpt must not be flagged"
        );
    }

    #[test]
    fn target_host_parsing() {
        assert_eq!(target_host("https://www.example.com:8443/x"), "www.example.com");
        assert_eq!(target_host("mail.example.com:587"), "mail.example.com");
        assert_eq!(target_host("https://[::1]:443"), "::1");
        assert_eq!(target_host("tests/data/valid.pem"), "");
    }

    #[test]
    fn public_hostname_heuristic() {
        assert!(is_public_hostname("www.example.com"));
        assert!(!is_public_hostname("10.0.0.1"));
        assert!(!is_public_hostname("vault.internal"));
        assert!(!is_public_hostname("localhost"));
        assert!(!is_public_hostname("printer.local"));
    }
}
