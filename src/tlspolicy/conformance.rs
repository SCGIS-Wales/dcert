//! Does an endpoint behave exactly like a named policy?
//!
//! The test runs in two parts. [`observe`] makes the handshakes, a few at a
//! time: a discovery handshake and two more that offer only RSA or only
//! ECDSA suites (to learn which certificate types the listener holds), each
//! protocol version on its own, each TLS 1.2 cipher and TLS 1.3 suite on its
//! own, and each key exchange group on its own. [`evaluate`] then compares a
//! policy with that observation, check by check, without touching the
//! network, so `--identify` can rank every catalogued policy against one
//! observation.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{PolicyCatalogue, TlsPolicy};
use crate::ciphers::{Cipher, NegotiatedCipher, Protocol};
use crate::cli::TlsVersionArg;
use crate::tls::{PqProbeRequest, ScanHandshake, TlsProbeOptions, scan_handshake};
use crate::tlsscan::{alert_reason, all_tls13_suites, broad_cipher_list, group_implemented, run_bounded};

/// The certificate key types a listener can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Rsa,
    Ecdsa,
}

impl KeyType {
    /// The key type of a leaf as `ScanHandshake::leaf_key` names it.
    fn of_leaf(leaf: &str) -> Option<Self> {
        if leaf.starts_with("RSA") {
            Some(Self::Rsa)
        } else if leaf.starts_with("EC ") {
            Some(Self::Ecdsa)
        } else {
            None
        }
    }

    /// The key type a TLS 1.2 cipher authenticates with, if it needs one.
    fn of_cipher(cipher: &Cipher) -> Option<Self> {
        match cipher.au {
            "RSA" => Some(Self::Rsa),
            "ECDSA" => Some(Self::Ecdsa),
            _ => None,
        }
    }
}

/// What one handshake showed.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Probe {
    Accepted {
        handshake: ScanHandshake,
    },
    Rejected {
        alert: String,
    },
    /// The handshake could not be attempted from here.
    NotTestable {
        reason: String,
    },
}

impl Probe {
    fn from(result: anyhow::Result<ScanHandshake>) -> Self {
        match result {
            Ok(handshake) => Self::Accepted { handshake },
            Err(e) => Self::Rejected {
                alert: alert_reason(&e.to_string()),
            },
        }
    }

    fn accepted(&self) -> Option<&ScanHandshake> {
        match self {
            Self::Accepted { handshake } => Some(handshake),
            _ => None,
        }
    }
}

/// Everything the handshakes showed, keyed for evaluation.
#[derive(Debug, Default, Serialize)]
pub struct Observation {
    pub key_types: BTreeSet<KeyType>,
    /// By version number, `1.2`.
    pub versions: BTreeMap<String, Probe>,
    /// TLS 1.2 ciphers by IANA name, offered with `min = max = 1.2`.
    pub tls12: BTreeMap<String, Probe>,
    /// TLS 1.3 suites by IANA name, offered with `min = max = 1.3`.
    pub tls13: BTreeMap<String, Probe>,
    /// Groups by name, offered at `groups_version`.
    pub groups: BTreeMap<String, Probe>,
    pub groups_version: Option<String>,
    pub handshakes: usize,
}

/// What to observe.
#[derive(Debug, Clone, Default)]
pub struct ObservePlan {
    /// Versions to offer, newest first.
    pub versions: Vec<TlsVersionArg>,
    /// Legacy versions in `versions` are offered only when set.
    pub allow_legacy_tls: bool,
    /// TLS 1.2 ciphers to offer, by IANA name.
    pub tls12: BTreeSet<String>,
    /// TLS 1.3 suites to offer, by IANA name.
    pub tls13: BTreeSet<String>,
    /// Groups to offer.
    pub groups: BTreeSet<String>,
    pub concurrency: usize,
}

/// One handshake setting.
struct Offer {
    min: TlsVersionArg,
    max: TlsVersionArg,
    cipher_list: String,
    cipher_suites: String,
    groups: Option<String>,
}

fn handshake(req: &PqProbeRequest<'_>, base: &TlsProbeOptions<'_>, offer: &Offer) -> Probe {
    let probe = TlsProbeOptions {
        no_verify: true,
        min_tls: Some(offer.min),
        max_tls: Some(offer.max),
        cipher_list: Some(&offer.cipher_list),
        cipher_suites: Some(&offer.cipher_suites),
        groups: offer.groups.as_deref(),
        ..*base
    };
    Probe::from(scan_handshake(req, &probe))
}

fn version_named(number: &str) -> Option<TlsVersionArg> {
    [
        TlsVersionArg::Tls1_0,
        TlsVersionArg::Tls1_1,
        TlsVersionArg::Tls1_2,
        TlsVersionArg::Tls1_3,
    ]
    .into_iter()
    .find(|v| v.number() == number)
}

/// Run the handshakes `plan` asks for.
pub fn observe(req: &PqProbeRequest<'_>, base: &TlsProbeOptions<'_>, plan: &ObservePlan) -> Observation {
    let suites = all_tls13_suites();
    let mut obs = Observation::default();
    let workers = plan.concurrency.max(1);

    // Discovery: the default handshake and RSA only and ECDSA only offers.
    let tls12_wanted = plan.versions.contains(&TlsVersionArg::Tls1_2);
    let mut discovery = vec![Offer {
        min: TlsVersionArg::Tls1_2,
        max: TlsVersionArg::Tls1_3,
        cipher_list: "ALL".to_string(),
        cipher_suites: suites.clone(),
        groups: None,
    }];
    if tls12_wanted {
        for auth in ["aRSA", "aECDSA"] {
            discovery.push(Offer {
                min: TlsVersionArg::Tls1_2,
                max: TlsVersionArg::Tls1_2,
                cipher_list: auth.to_string(),
                cipher_suites: suites.clone(),
                groups: None,
            });
        }
    }
    for probe in run_bounded(&discovery, workers, |offer| handshake(req, base, offer)) {
        obs.handshakes += 1;
        if let Some(key) = probe
            .accepted()
            .and_then(|h| h.leaf_key.as_deref())
            .and_then(KeyType::of_leaf)
        {
            obs.key_types.insert(key);
        }
    }

    // Versions, each on its own.
    let versions: Vec<TlsVersionArg> = plan.versions.clone();
    let probes = run_bounded(&versions, workers, |&version| {
        if version.is_legacy() && !plan.allow_legacy_tls {
            return Probe::NotTestable {
                reason: "TLS 1.0 and 1.1 are tested only with --allow-legacy-tls".to_string(),
            };
        }
        handshake(
            req,
            base,
            &Offer {
                min: version,
                max: version,
                cipher_list: broad_cipher_list(version).to_string(),
                cipher_suites: suites.clone(),
                groups: None,
            },
        )
    });
    for (version, probe) in versions.iter().zip(probes) {
        if !matches!(probe, Probe::NotTestable { .. }) {
            obs.handshakes += 1;
        }
        obs.versions.insert(version.number().to_string(), probe);
    }
    let accepted = |v: &str| obs.versions.get(v).is_some_and(|p| p.accepted().is_some());

    // TLS 1.2 ciphers and TLS 1.3 suites, each on its own.
    let suite_probe = |name: &String, version: TlsVersionArg| -> Probe {
        let Ok(cipher) = Cipher::parse(name) else {
            return Probe::NotTestable {
                reason: format!("{name} is not in the cipher table"),
            };
        };
        let Some(openssl) = cipher.openssl.filter(|_| cipher.offerable()) else {
            return Probe::NotTestable {
                reason: format!("the linked {} cannot offer {name}", openssl::version::version()),
            };
        };
        let (cipher_list, cipher_suites) = if version == TlsVersionArg::Tls1_3 {
            (broad_cipher_list(version).to_string(), openssl.to_string())
        } else {
            (openssl.to_string(), suites.clone())
        };
        handshake(
            req,
            base,
            &Offer {
                min: version,
                max: version,
                cipher_list,
                cipher_suites,
                groups: None,
            },
        )
    };
    if accepted("1.2") {
        let names: Vec<String> = plan.tls12.iter().cloned().collect();
        for (name, probe) in names
            .iter()
            .zip(run_bounded(&names, workers, |n| suite_probe(n, TlsVersionArg::Tls1_2)))
        {
            obs.handshakes += usize::from(!matches!(probe, Probe::NotTestable { .. }));
            obs.tls12.insert(name.clone(), probe);
        }
    }
    if accepted("1.3") {
        let names: Vec<String> = plan.tls13.iter().cloned().collect();
        for (name, probe) in names
            .iter()
            .zip(run_bounded(&names, workers, |n| suite_probe(n, TlsVersionArg::Tls1_3)))
        {
            obs.handshakes += usize::from(!matches!(probe, Probe::NotTestable { .. }));
            obs.tls13.insert(name.clone(), probe);
        }
    }

    // Groups, each on its own, at TLS 1.3 whenever the server speaks it (the
    // ML-KEM hybrids exist only there), even if `versions` left it out.
    let speaks_13 = match obs.versions.get("1.3") {
        Some(probe) => probe.accepted().is_some(),
        None if plan.groups.is_empty() => false,
        None => {
            let probe = handshake(
                req,
                base,
                &Offer {
                    min: TlsVersionArg::Tls1_3,
                    max: TlsVersionArg::Tls1_3,
                    cipher_list: broad_cipher_list(TlsVersionArg::Tls1_3).to_string(),
                    cipher_suites: suites.clone(),
                    groups: None,
                },
            );
            obs.handshakes += 1;
            probe.accepted().is_some()
        }
    };
    let group_version = if speaks_13 {
        Some(TlsVersionArg::Tls1_3)
    } else {
        Some(TlsVersionArg::Tls1_2).filter(|v| accepted(v.number()))
    };
    if let Some(version) = group_version {
        obs.groups_version = Some(version.number().to_string());
        let names: Vec<String> = plan.groups.iter().cloned().collect();
        let probes = run_bounded(&names, workers, |group| {
            if !group_implemented(group) {
                return Probe::NotTestable {
                    reason: format!("the linked {} does not implement {group}", openssl::version::version()),
                };
            }
            handshake(
                req,
                base,
                &Offer {
                    min: version,
                    max: version,
                    cipher_list: broad_cipher_list(version).to_string(),
                    cipher_suites: suites.clone(),
                    groups: Some(group.clone()),
                },
            )
        });
        for (name, probe) in names.iter().zip(probes) {
            obs.handshakes += usize::from(!matches!(probe, Probe::NotTestable { .. }));
            obs.groups.insert(name.clone(), probe);
        }
    }
    obs
}

/// The handshakes a test of `policies` needs: every version in `versions`,
/// every catalogued TLS 1.2 cipher (to test exclusions too), every TLS 1.3
/// suite the linked OpenSSL implements, each policy group, `X25519` and the
/// RFC 10024 hybrids.
pub fn plan_for(
    policies: &[&TlsPolicy],
    catalogue: &PolicyCatalogue,
    versions: &[TlsVersionArg],
    allow_legacy_tls: bool,
    concurrency: usize,
) -> ObservePlan {
    let mut plan = ObservePlan {
        versions: versions.to_vec(),
        allow_legacy_tls,
        concurrency,
        ..ObservePlan::default()
    };
    if versions.contains(&TlsVersionArg::Tls1_2) {
        plan.tls12 = catalogue
            .policies
            .iter()
            .flat_map(|p| p.tls12_ciphers.iter().cloned())
            .collect();
    }
    if versions.contains(&TlsVersionArg::Tls1_3) {
        plan.tls13 = crate::ciphers::all()
            .iter()
            .filter(|c| c.protocol == Protocol::Tls13 && c.openssl.is_some())
            .map(|c| c.iana.to_string())
            .collect();
        plan.tls13
            .extend(policies.iter().flat_map(|p| p.tls13_suites.iter().cloned()));
    }
    plan.groups = policies.iter().flat_map(|p| p.groups.iter().cloned()).collect();
    plan.groups.insert("X25519".to_string());
    plan.groups
        .extend(crate::keyex::RFC10024_HYBRID_GROUPS.iter().map(|g| (*g).to_string()));
    plan
}

/// What the policy says should happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Expected {
    Accept,
    Reject,
}

/// How a check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail,
    /// This build or these flags cannot run the check.
    NotTestable,
    /// The check does not apply to this listener (for example an ECDSA
    /// cipher on a listener with only an RSA certificate).
    NotApplicable,
}

/// The kind of a check, in the order the report lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    Protocol,
    Tls12Cipher,
    Tls12Excluded,
    Tls13Suite,
    Tls13Excluded,
    Group,
    ClassicalFallback,
    HybridExcluded,
}

/// One named check.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub kind: CheckKind,
    /// `TLS 1.2`, a cipher's IANA name or a group name.
    pub subject: String,
    /// The suite in every notation, for cipher and suite checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<NegotiatedCipher>,
    pub expected: Expected,
    /// `accept`, `reject`, `accept (negotiated X)` or why it did not run.
    pub observed: String,
    pub evidence: String,
    pub outcome: Outcome,
}

impl Check {
    /// One line naming what deviated, e.g. `TLS 1.2 accepted`.
    pub fn deviation(&self) -> String {
        let subject = match &self.cipher {
            Some(c) => c.display(),
            None => self.subject.clone(),
        };
        match self.expected {
            Expected::Accept => format!("{subject} refused ({})", self.evidence),
            Expected::Reject => format!("{subject} accepted"),
        }
    }
}

/// The overall answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Conformant,
    NonConformant,
    Inconclusive,
}

/// A policy compared with an observation.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyReport {
    pub policy: String,
    pub provider: super::PolicyProvider,
    pub verdict: Verdict,
    /// Failed checks, one line each.
    pub deviations: Vec<String>,
    pub key_types: Vec<KeyType>,
    pub checks: Vec<Check>,
}

impl PolicyReport {
    pub fn count(&self, outcome: Outcome) -> usize {
        self.checks.iter().filter(|c| c.outcome == outcome).count()
    }

    /// Fewest failures first, then the most passed checks: a policy that
    /// asserts more and still matches is the better fit. Untestable checks
    /// count for nothing, so a policy is not ranked down for stating groups
    /// the linked OpenSSL cannot offer.
    pub fn rank_key(&self) -> (usize, std::cmp::Reverse<usize>) {
        (self.count(Outcome::Fail), std::cmp::Reverse(self.count(Outcome::Pass)))
    }
}

/// What an accepted handshake must have negotiated, and how to read it.
type Wanted<'a> = (&'a str, fn(&ScanHandshake) -> String);

fn names_equal(a: &str, b: &str) -> bool {
    let canonical = |n: &str| match n.to_ascii_lowercase().as_str() {
        "prime256v1" | "p-256" => "secp256r1".to_string(),
        "p-384" => "secp384r1".to_string(),
        "p-521" => "secp521r1".to_string(),
        other => other.to_string(),
    };
    canonical(a) == canonical(b)
}

/// Compare `probe` with `expected`. `negotiated` names what an acceptance
/// must have negotiated, when that matters.
fn judge(expected: Expected, probe: Option<&Probe>, negotiated: Option<Wanted<'_>>) -> (String, String, Outcome) {
    match (expected, probe) {
        (_, None) => ("not run".to_string(), String::new(), Outcome::NotTestable),
        (_, Some(Probe::NotTestable { reason })) => ("not run".to_string(), reason.clone(), Outcome::NotTestable),
        (Expected::Accept, Some(Probe::Accepted { handshake })) => {
            let got = negotiated.map(|(_, read)| read(handshake));
            match (negotiated, got) {
                (Some((want, _)), Some(got)) if !names_equal(want, &got) => (
                    format!("accept (negotiated {got})"),
                    format!("{want} was offered alone but {got} was negotiated"),
                    Outcome::Fail,
                ),
                _ => ("accept".to_string(), handshake_evidence(handshake), Outcome::Pass),
            }
        }
        (Expected::Accept, Some(Probe::Rejected { alert })) => ("reject".to_string(), alert.clone(), Outcome::Fail),
        (Expected::Reject, Some(Probe::Rejected { alert })) => ("reject".to_string(), alert.clone(), Outcome::Pass),
        (Expected::Reject, Some(Probe::Accepted { handshake })) => {
            ("accept".to_string(), handshake_evidence(handshake), Outcome::Fail)
        }
    }
}

fn handshake_evidence(h: &ScanHandshake) -> String {
    let mut parts = vec![h.version.clone(), h.cipher.openssl.clone()];
    parts.extend(h.group.clone());
    parts.extend(h.leaf_key.clone());
    parts.join(", ")
}

fn read_cipher(h: &ScanHandshake) -> String {
    h.cipher.iana.clone().unwrap_or_else(|| h.cipher.openssl.clone())
}

fn read_group(h: &ScanHandshake) -> String {
    h.group.clone().unwrap_or_default()
}

fn record(cipher: &Cipher) -> NegotiatedCipher {
    NegotiatedCipher::new(
        cipher.openssl.unwrap_or(cipher.iana),
        Some(cipher.iana),
        Some(cipher.code),
    )
}

/// Compare `policy` with `obs`, limited to `versions`.
pub fn evaluate(
    policy: &TlsPolicy,
    obs: &Observation,
    versions: &[TlsVersionArg],
    catalogue: &PolicyCatalogue,
) -> PolicyReport {
    let mut checks = Vec::new();
    let tested = |v: &str| versions.iter().any(|x| x.number() == v);
    let version_accepted = |v: &str| obs.versions.get(v).is_some_and(|p| p.accepted().is_some());

    // Protocol versions.
    for version in versions {
        let number = version.number();
        let expected = if policy.allows(number) {
            Expected::Accept
        } else {
            Expected::Reject
        };
        let (observed, evidence, outcome) = judge(expected, obs.versions.get(number), None);
        checks.push(Check {
            kind: CheckKind::Protocol,
            subject: version.label().to_string(),
            cipher: None,
            expected,
            observed,
            evidence,
            outcome,
        });
    }

    // Suite checks share the applicability rules.
    let mut suite_check =
        |kind: CheckKind, name: &str, expected: Expected, version: &str, map: &BTreeMap<String, Probe>| {
            let Ok(cipher) = Cipher::parse(name) else { return };
            let cipher_record = record(cipher);
            let not_applicable = |evidence: String| Check {
                kind,
                subject: cipher.iana.to_string(),
                cipher: Some(cipher_record.clone()),
                expected,
                observed: "not run".to_string(),
                evidence,
                outcome: Outcome::NotApplicable,
            };
            if !version_accepted(version) {
                checks.push(not_applicable(format!(
                    "TLS {version} was refused, so its check covers this"
                )));
                return;
            }
            if let Some(key) = KeyType::of_cipher(cipher)
                && !obs.key_types.is_empty()
                && !obs.key_types.contains(&key)
            {
                checks.push(not_applicable(format!("the listener holds no {key:?} certificate")));
                return;
            }
            let (observed, evidence, outcome) = judge(expected, map.get(cipher.iana), Some((cipher.iana, read_cipher)));
            checks.push(Check {
                kind,
                subject: cipher.iana.to_string(),
                cipher: Some(cipher_record),
                expected,
                observed,
                evidence,
                outcome,
            });
        };

    if tested("1.2") && policy.allows("1.2") {
        for name in &policy.tls12_ciphers {
            suite_check(CheckKind::Tls12Cipher, name, Expected::Accept, "1.2", &obs.tls12);
        }
        let others: BTreeSet<&String> = catalogue
            .policies
            .iter()
            .flat_map(|p| p.tls12_ciphers.iter())
            .filter(|c| !policy.tls12_ciphers.contains(c))
            .collect();
        for name in others {
            suite_check(CheckKind::Tls12Excluded, name, Expected::Reject, "1.2", &obs.tls12);
        }
    }
    if tested("1.3") && policy.allows("1.3") {
        for name in &policy.tls13_suites {
            suite_check(CheckKind::Tls13Suite, name, Expected::Accept, "1.3", &obs.tls13);
        }
        let others: Vec<&String> = obs.tls13.keys().filter(|s| !policy.tls13_suites.contains(s)).collect();
        for name in others {
            suite_check(CheckKind::Tls13Excluded, name, Expected::Reject, "1.3", &obs.tls13);
        }
    }

    // Groups at the newest accepted version.
    let mut group_check = |kind: CheckKind, group: &str, expected: Expected| {
        let probe = obs.groups.get(group);
        let tls12_only = obs.groups_version.as_deref() == Some("1.2");
        let (observed, evidence, outcome) = match probe {
            None if obs.groups_version.is_none() => (
                "not run".to_string(),
                "no protocol version was accepted".to_string(),
                Outcome::NotApplicable,
            ),
            _ if tls12_only && group.contains("MLKEM") => (
                "not run".to_string(),
                "ML-KEM groups exist only in TLS 1.3, which the server refused".to_string(),
                Outcome::NotApplicable,
            ),
            _ => {
                let negotiated =
                    (expected == Expected::Accept).then_some((group, read_group as fn(&ScanHandshake) -> String));
                judge(expected, probe, negotiated)
            }
        };
        checks.push(Check {
            kind,
            subject: group.to_string(),
            cipher: None,
            expected,
            observed,
            evidence,
            outcome,
        });
    };
    for group in &policy.groups {
        group_check(CheckKind::Group, group, Expected::Accept);
    }
    if policy.post_quantum {
        if !policy.groups.iter().any(|g| names_equal(g, "X25519")) {
            group_check(CheckKind::ClassicalFallback, "X25519", Expected::Accept);
        }
    } else {
        for group in crate::keyex::RFC10024_HYBRID_GROUPS {
            if !policy.groups.iter().any(|g| names_equal(g, group)) {
                group_check(CheckKind::HybridExcluded, group, Expected::Reject);
            }
        }
    }

    checks.sort_by_key(|c| c.kind);
    let failed: Vec<String> = checks
        .iter()
        .filter(|c| c.outcome == Outcome::Fail)
        .map(Check::deviation)
        .collect();
    let verdict = if !failed.is_empty() {
        Verdict::NonConformant
    } else if checks.iter().any(|c| c.outcome == Outcome::NotTestable) {
        Verdict::Inconclusive
    } else {
        Verdict::Conformant
    };
    PolicyReport {
        policy: policy.id.clone(),
        provider: policy.provider,
        verdict,
        deviations: failed,
        key_types: obs.key_types.iter().copied().collect(),
        checks,
    }
}

/// How well each catalogued policy matches one observation, best first.
pub fn rank(obs: &Observation, versions: &[TlsVersionArg], catalogue: &PolicyCatalogue) -> Vec<PolicyReport> {
    let mut reports: Vec<PolicyReport> = catalogue
        .policies
        .iter()
        .map(|p| evaluate(p, obs, versions, catalogue))
        .collect();
    reports.sort_by(|a, b| (a.rank_key(), a.provider, &a.policy).cmp(&(b.rank_key(), b.provider, &b.policy)));
    reports
}

/// Every version, newest first, or those named.
pub fn versions_or_all(named: &[TlsVersionArg]) -> Vec<TlsVersionArg> {
    let mut versions: Vec<TlsVersionArg> = if named.is_empty() {
        vec![
            TlsVersionArg::Tls1_3,
            TlsVersionArg::Tls1_2,
            TlsVersionArg::Tls1_1,
            TlsVersionArg::Tls1_0,
        ]
    } else {
        named.to_vec()
    };
    versions.sort_unstable_by(|a, b| b.cmp(a));
    versions.dedup();
    versions
}

/// Look a version up by its number, for callers holding strings.
pub fn parse_version(number: &str) -> Option<TlsVersionArg> {
    version_named(number)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::tlspolicy::PolicyProvider;

    const RES_PQ: &str = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09";
    const TLS13_PQ: &str = "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09";

    fn catalogue() -> &'static PolicyCatalogue {
        PolicyCatalogue::builtin().unwrap()
    }

    fn policy(id: &str) -> &'static TlsPolicy {
        catalogue().get(id, PolicyProvider::AwsAlb).unwrap()
    }

    fn accepted(version: &str, cipher: &str, group: &str, leaf: &str) -> Probe {
        let c = Cipher::parse(cipher).unwrap();
        Probe::Accepted {
            handshake: ScanHandshake {
                version: version.to_string(),
                cipher: NegotiatedCipher::new(c.openssl.unwrap(), Some(c.iana), Some(c.code)),
                group: Some(group.to_string()),
                leaf_key: Some(leaf.to_string()),
            },
        }
    }

    fn rejected() -> Probe {
        Probe::Rejected {
            alert: "handshake failure".to_string(),
        }
    }

    /// The observation of a server that behaves exactly like `id`, holding
    /// the given key types, with ML-KEM testable or not.
    fn emulate(id: &str, keys: &[KeyType], mlkem: bool) -> Observation {
        let p = policy(id);
        let leaf = |k: KeyType| if k == KeyType::Rsa { "RSA 2048" } else { "EC prime256v1" };
        let mut obs = Observation {
            key_types: keys.iter().copied().collect(),
            ..Observation::default()
        };
        for v in ["1.3", "1.2", "1.1", "1.0"] {
            let probe = if p.allows(v) {
                accepted(&format!("TLSv{v}"), "TLS_AES_128_GCM_SHA256", "X25519", leaf(keys[0]))
            } else {
                rejected()
            };
            obs.versions.insert(v.to_string(), probe);
        }
        let plan = plan_for(&[p], catalogue(), &versions_or_all(&[]), true, 4);
        for name in &plan.tls12 {
            let c = Cipher::parse(name).unwrap();
            let holds = KeyType::of_cipher(c).is_none_or(|k| keys.contains(&k));
            let probe = if p.tls12_ciphers.contains(name) && holds {
                accepted(
                    "TLSv1.2",
                    name,
                    "X25519",
                    leaf(KeyType::of_cipher(c).unwrap_or(keys[0])),
                )
            } else {
                rejected()
            };
            obs.tls12.insert(name.clone(), probe);
        }
        for name in &plan.tls13 {
            let probe = if p.tls13_suites.contains(name) {
                accepted("TLSv1.3", name, "X25519", leaf(keys[0]))
            } else {
                rejected()
            };
            obs.tls13.insert(name.clone(), probe);
        }
        obs.groups_version = Some("1.3".to_string());
        for group in &plan.groups {
            let probe = if group.contains("MLKEM") && !mlkem {
                Probe::NotTestable {
                    reason: "no ML-KEM".to_string(),
                }
            } else if p.groups.contains(group) || group == "X25519" {
                accepted("TLSv1.3", "TLS_AES_128_GCM_SHA256", group, leaf(keys[0]))
            } else {
                rejected()
            };
            obs.groups.insert(group.clone(), probe);
        }
        obs
    }

    #[test]
    fn an_exact_server_is_conformant_and_ml_kem_gaps_are_inconclusive() {
        let all = versions_or_all(&[]);
        let both = [KeyType::Rsa, KeyType::Ecdsa];
        let report = evaluate(policy(RES_PQ), &emulate(RES_PQ, &both, true), &all, catalogue());
        // TLS 1.0 and 1.1 were observed (the emulation allows legacy).
        assert_eq!(report.verdict, Verdict::Conformant, "{:?}", report.deviations);
        let no_mlkem = evaluate(policy(RES_PQ), &emulate(RES_PQ, &both, false), &all, catalogue());
        assert_eq!(no_mlkem.verdict, Verdict::Inconclusive);
        assert!(no_mlkem.deviations.is_empty());
    }

    #[test]
    fn ciphers_for_a_missing_key_type_are_not_applicable() {
        let report = evaluate(
            policy(RES_PQ),
            &emulate(RES_PQ, &[KeyType::Rsa], true),
            &versions_or_all(&[]),
            catalogue(),
        );
        assert_eq!(report.verdict, Verdict::Conformant, "{:?}", report.deviations);
        let ecdsa = report
            .checks
            .iter()
            .find(|c| c.subject == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
            .unwrap();
        assert_eq!(ecdsa.outcome, Outcome::NotApplicable);
    }

    #[test]
    fn an_extra_tls12_version_or_cipher_is_a_named_deviation() {
        let both = [KeyType::Rsa, KeyType::Ecdsa];
        let all = versions_or_all(&[]);
        let mut tls12_on = emulate(TLS13_PQ, &both, true);
        tls12_on.versions.insert(
            "1.2".to_string(),
            accepted("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", "X25519", "RSA 2048"),
        );
        let report = evaluate(policy(TLS13_PQ), &tls12_on, &all, catalogue());
        assert_eq!(report.verdict, Verdict::NonConformant);
        assert_eq!(report.deviations, ["TLS 1.2 accepted"]);

        let mut cbc = emulate(RES_PQ, &both, true);
        cbc.tls12.insert(
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256".to_string(),
            accepted("TLSv1.2", "ECDHE-RSA-AES128-SHA256", "X25519", "RSA 2048"),
        );
        let report = evaluate(policy(RES_PQ), &cbc, &all, catalogue());
        assert_eq!(report.verdict, Verdict::NonConformant);
        assert_eq!(report.deviations.len(), 1, "{:?}", report.deviations);
        let line = &report.deviations[0];
        for notation in [
            "ECDHE-RSA-AES128-SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "0xC027",
        ] {
            assert!(line.contains(notation), "{line}");
        }
    }

    #[test]
    fn legacy_versions_without_the_flag_are_not_testable() {
        let mut obs = emulate(RES_PQ, &[KeyType::Rsa], true);
        for v in ["1.1", "1.0"] {
            obs.versions.insert(
                v.to_string(),
                Probe::NotTestable {
                    reason: "needs --allow-legacy-tls".to_string(),
                },
            );
        }
        let report = evaluate(policy(RES_PQ), &obs, &versions_or_all(&[]), catalogue());
        assert_eq!(report.verdict, Verdict::Inconclusive);
        let only_modern = evaluate(
            policy(RES_PQ),
            &obs,
            &[TlsVersionArg::Tls1_3, TlsVersionArg::Tls1_2],
            catalogue(),
        );
        assert_eq!(only_modern.verdict, Verdict::Conformant);
    }

    #[test]
    fn a_negotiated_suite_other_than_the_one_offered_fails() {
        let mut obs = emulate(TLS13_PQ, &[KeyType::Rsa], true);
        obs.tls13.insert(
            "TLS_AES_256_GCM_SHA384".to_string(),
            accepted("TLSv1.3", "TLS_AES_128_GCM_SHA256", "X25519", "RSA 2048"),
        );
        let report = evaluate(policy(TLS13_PQ), &obs, &[TlsVersionArg::Tls1_3], catalogue());
        assert_eq!(report.verdict, Verdict::NonConformant);
    }

    #[test]
    fn identify_ranks_the_emulated_policy_first() {
        let obs = emulate(RES_PQ, &[KeyType::Rsa, KeyType::Ecdsa], true);
        let ranked = rank(&obs, &versions_or_all(&[]), catalogue());
        assert_eq!(ranked[0].count(Outcome::Fail), 0);
        assert!(
            ranked
                .iter()
                .take_while(|r| r.count(Outcome::Fail) == 0)
                .any(|r| r.policy == RES_PQ)
        );
        let fips = ranked
            .iter()
            .find(|r| {
                r.policy == "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09" && r.provider == PolicyProvider::AwsAlb
            })
            .unwrap();
        assert_eq!(fips.deviations, ["TLS_CHACHA20_POLY1305_SHA256 (0x1303) accepted"]);
    }

    #[test]
    fn group_names_compare_by_curve() {
        assert!(names_equal("prime256v1", "secp256r1"));
        assert!(names_equal("x25519", "X25519"));
        assert!(!names_equal("secp384r1", "secp256r1"));
        assert_eq!(parse_version("1.2"), Some(TlsVersionArg::Tls1_2));
        assert_eq!(
            versions_or_all(&[TlsVersionArg::Tls1_2, TlsVersionArg::Tls1_3, TlsVersionArg::Tls1_2]),
            [TlsVersionArg::Tls1_3, TlsVersionArg::Tls1_2]
        );
    }
}
