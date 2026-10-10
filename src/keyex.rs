//! TLS key exchange groups, post quantum classification and TLS profiles.
//!
//! Hybrid post quantum key agreement for TLS 1.3 is standardised in RFC 10024
//! (August 2026): `X25519MLKEM768` (0x11EC, recommended), `SecP256r1MLKEM768`
//! (0x11EB) and `SecP384r1MLKEM1024` (0x11ED). Pure ML-KEM groups
//! (`MLKEM512`, `MLKEM768`, `MLKEM1024`) are still an Internet-Draft
//! (draft-ietf-tls-mlkem). The pre standard `X25519Kyber768Draft00` (0x6399)
//! is obsolete. OpenSSL 3.5 (April 2025, LTS) implements ML-KEM and offers
//! `X25519MLKEM768` by default; earlier releases cannot negotiate any post
//! quantum group at all, which is why every function here degrades to
//! "unknown" or "not testable" rather than failing.

use serde::Serialize;

/// Minimum `OPENSSL_VERSION_NUMBER` with ML-KEM support (3.5.0).
const OPENSSL_MLKEM_MIN: i64 = 0x3050_0000;

/// RFC 10024 hybrid groups, most preferred first, in OpenSSL group list form.
pub const RFC10024_HYBRID_GROUPS: &[&str] = &["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"];

/// Pure ML-KEM group names (draft-ietf-tls-mlkem).
pub const PURE_MLKEM_GROUPS: &[&str] = &["MLKEM512", "MLKEM768", "MLKEM1024"];

/// Pre standard hybrid names and what replaced them.
pub const OBSOLETE_PQ_GROUPS: &[(&str, &str)] = &[
    ("X25519Kyber768Draft00", "X25519MLKEM768 (RFC 10024)"),
    ("SecP256r1Kyber768Draft00", "SecP256r1MLKEM768 (RFC 10024)"),
    ("X25519Kyber512Draft00", "X25519MLKEM768 (RFC 10024)"),
];

/// Classification of the negotiated key exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyExchangeClass {
    /// Classical plus ML-KEM, as standardised in RFC 10024.
    HybridPq,
    /// ML-KEM on its own (draft-ietf-tls-mlkem).
    PurePq,
    /// Pre standard Kyber draft group; obsolete and no longer offered by browsers.
    ObsoletePq,
    /// ECDHE, X25519, X448 or finite field DHE: breakable by a cryptographically
    /// relevant quantum computer.
    Classical,
    /// Group name not available from the linked OpenSSL (older than 3.2) or
    /// not recognised.
    #[default]
    Unknown,
}

impl KeyExchangeClass {
    /// Human readable label used in pretty output.
    pub fn label(self) -> &'static str {
        match self {
            KeyExchangeClass::HybridPq => "hybrid post quantum",
            KeyExchangeClass::PurePq => "pure post quantum",
            KeyExchangeClass::ObsoletePq => "obsolete pre standard post quantum",
            KeyExchangeClass::Classical => "classical",
            KeyExchangeClass::Unknown => "unknown",
        }
    }

    /// `true` for any ML-KEM based group, hybrid or pure, standard or draft.
    pub fn is_post_quantum(self) -> bool {
        matches!(
            self,
            KeyExchangeClass::HybridPq | KeyExchangeClass::PurePq | KeyExchangeClass::ObsoletePq
        )
    }
}

/// Classify a group by its OpenSSL or IANA name (case insensitive).
pub fn classify_group(name: &str) -> KeyExchangeClass {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return KeyExchangeClass::Unknown;
    }
    if RFC10024_HYBRID_GROUPS.iter().any(|g| g.eq_ignore_ascii_case(trimmed)) {
        return KeyExchangeClass::HybridPq;
    }
    if PURE_MLKEM_GROUPS.iter().any(|g| g.eq_ignore_ascii_case(trimmed)) {
        return KeyExchangeClass::PurePq;
    }
    if OBSOLETE_PQ_GROUPS.iter().any(|(g, _)| g.eq_ignore_ascii_case(trimmed)) {
        return KeyExchangeClass::ObsoletePq;
    }
    let lower = trimmed.to_ascii_lowercase();
    let classical = lower == "x25519"
        || lower == "x448"
        || lower.starts_with("secp")
        || lower.starts_with("prime")
        || lower.starts_with("p-")
        || lower.starts_with("brainpool")
        || lower.starts_with("ffdhe")
        || lower.starts_with("dh");
    if classical {
        KeyExchangeClass::Classical
    } else if lower.contains("mlkem") || lower.contains("kyber") {
        // An ML-KEM group name this build does not list yet (for example a
        // future hybrid with X448): still post quantum.
        KeyExchangeClass::HybridPq
    } else {
        KeyExchangeClass::Unknown
    }
}

/// The replacement for an obsolete draft group, when `name` is one.
pub fn obsolete_group_replacement(name: &str) -> Option<&'static str> {
    OBSOLETE_PQ_GROUPS
        .iter()
        .find(|(g, _)| g.eq_ignore_ascii_case(name.trim()))
        .map(|(_, replacement)| *replacement)
}

/// Whether the linked OpenSSL can negotiate ML-KEM groups (3.5.0 or later).
pub fn openssl_supports_mlkem() -> bool {
    openssl::version::number() >= OPENSSL_MLKEM_MIN
}

/// Whether the linked OpenSSL reports the negotiated group name
/// (`SSL_get0_group_name`, 3.2.0 or later).
pub fn openssl_reports_group_name() -> bool {
    cfg!(dcert_ossl320)
}

/// One line describing the linked OpenSSL and its post quantum capability,
/// shown by `dcert --version` and in debug output.
pub fn openssl_summary() -> String {
    let pq = if openssl_supports_mlkem() {
        "post quantum key exchange: available (ML-KEM, RFC 10024 hybrids)"
    } else {
        "post quantum key exchange: not available (needs OpenSSL 3.5 or later)"
    };
    format!("{} ({pq})", openssl::version::version())
}

/// OpenSSL group list offering only the RFC 10024 hybrids, used by `--pq-probe`.
pub fn pq_probe_groups() -> String {
    RFC10024_HYBRID_GROUPS.join(":")
}

/// Outcome of the opt in post quantum probe (`--pq-probe`).
#[derive(Debug, Clone, Serialize)]
pub struct PqProbeResult {
    /// `supported`, `not_supported` or `not_testable`.
    pub status: PqProbeStatus,
    /// Group the server agreed to when `status` is `supported`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Groups that were offered.
    pub offered: Vec<String>,
    /// Explanation suitable for display.
    pub detail: String,
}

/// Status of the post quantum probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqProbeStatus {
    Supported,
    NotSupported,
    NotTestable,
}

impl PqProbeResult {
    /// Result for a build whose OpenSSL cannot offer ML-KEM.
    pub fn not_testable() -> Self {
        Self {
            status: PqProbeStatus::NotTestable,
            group: None,
            offered: Vec::new(),
            detail: format!(
                "not testable with {}: ML-KEM groups need OpenSSL 3.5 or later (build with the `vendored` feature or install a newer libssl)",
                openssl::version::version()
            ),
        }
    }

    /// Result when the probe cannot run for a reason other than the OpenSSL
    /// version (for example a `--max-tls 1.2` bound).
    pub fn not_testable_with(detail: String) -> Self {
        Self {
            status: PqProbeStatus::NotTestable,
            group: None,
            offered: Vec::new(),
            detail,
        }
    }

    fn offered_groups() -> Vec<String> {
        RFC10024_HYBRID_GROUPS.iter().map(ToString::to_string).collect()
    }

    /// The server completed a handshake with a hybrid group.
    pub fn supported(group: String) -> Self {
        Self {
            detail: format!("server negotiated {group} when only RFC 10024 hybrid groups were offered"),
            status: PqProbeStatus::Supported,
            group: Some(group),
            offered: Self::offered_groups(),
        }
    }

    /// The handshake failed (or fell back to something else) when only
    /// hybrid groups were offered.
    pub fn not_supported(reason: &str) -> Self {
        Self {
            status: PqProbeStatus::NotSupported,
            group: None,
            offered: Self::offered_groups(),
            detail: format!("server does not accept any RFC 10024 hybrid group: {reason}"),
        }
    }
}

/// Named TLS client profiles following the Mozilla TLS configurator (v6.0,
/// May 2026): every remaining suite offers forward secrecy and AEAD, and
/// `X25519MLKEM768` is the recommended first group in all profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TlsProfile {
    /// TLS 1.3 only.
    Modern,
    /// TLS 1.2 and 1.3 with forward secret AEAD suites.
    Intermediate,
}

/// Settings a profile expands to. Explicit flags on the command line always
/// win over these values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSettings {
    pub min_tls: crate::cli::TlsVersionArg,
    /// TLS 1.2 cipher list (`None` for TLS 1.3 only profiles).
    pub cipher_list: Option<String>,
    pub cipher_suites: String,
    pub groups: String,
}

const TLS13_SUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";

const INTERMEDIATE_TLS12_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";

const CLASSICAL_GROUPS: &str = "X25519:prime256v1:secp384r1";

impl TlsProfile {
    /// Expand the profile. The ML-KEM hybrid is included only when the linked
    /// OpenSSL can offer it; older releases reject unknown group names.
    pub fn settings(self) -> ProfileSettings {
        self.settings_for(openssl_supports_mlkem())
    }

    fn settings_for(self, mlkem_available: bool) -> ProfileSettings {
        let groups = if mlkem_available {
            format!("X25519MLKEM768:{CLASSICAL_GROUPS}")
        } else {
            CLASSICAL_GROUPS.to_string()
        };
        match self {
            TlsProfile::Modern => ProfileSettings {
                min_tls: crate::cli::TlsVersionArg::Tls1_3,
                cipher_list: None,
                cipher_suites: TLS13_SUITES.to_string(),
                groups,
            },
            TlsProfile::Intermediate => ProfileSettings {
                min_tls: crate::cli::TlsVersionArg::Tls1_2,
                cipher_list: Some(INTERMEDIATE_TLS12_CIPHERS.to_string()),
                cipher_suites: TLS13_SUITES.to_string(),
                groups,
            },
        }
    }
}

/// TLS client settings after a profile (if any) and the explicit flags have
/// been combined. Explicit flags always win over the profile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveTlsSettings {
    pub min_tls: Option<crate::cli::TlsVersionArg>,
    pub cipher_list: Option<String>,
    pub cipher_suites: Option<String>,
    pub groups: Option<String>,
}

/// Combine `--tls-profile` with the explicit `--min-tls`, `--cipher-list`,
/// `--cipher-suites` and `--groups` flags.
pub fn effective_tls_settings(
    profile: Option<TlsProfile>,
    min_tls: Option<crate::cli::TlsVersionArg>,
    cipher_list: Option<&str>,
    cipher_suites: Option<&str>,
    groups: Option<&str>,
) -> EffectiveTlsSettings {
    let base = profile.map(TlsProfile::settings);
    EffectiveTlsSettings {
        min_tls: min_tls.or_else(|| base.as_ref().map(|b| b.min_tls)),
        cipher_list: cipher_list
            .map(ToString::to_string)
            .or_else(|| base.as_ref().and_then(|b| b.cipher_list.clone())),
        cipher_suites: cipher_suites
            .map(ToString::to_string)
            .or_else(|| base.as_ref().map(|b| b.cipher_suites.clone())),
        groups: groups
            .map(ToString::to_string)
            .or_else(|| base.as_ref().map(|b| b.groups.clone())),
    }
}

/// Validate a user supplied OpenSSL group list before it reaches libssl, so
/// a typo produces a clear error instead of an opaque handshake failure.
/// Accepts the OpenSSL 3.5 prefixes `*` (send key share), `?` (ignore if
/// unsupported) and `-` (remove), the `/` tuple separator and `DEFAULT`.
pub fn validate_groups_list(groups: &str) -> Result<(), String> {
    let trimmed = groups.trim();
    if trimmed.is_empty() {
        return Err("--groups must not be empty".to_string());
    }
    if trimmed.len() > 1024 {
        return Err("--groups is too long (maximum 1024 characters)".to_string());
    }
    for entry in trimmed.split([':', '/']) {
        let name = entry.trim().trim_start_matches(['*', '?', '-']);
        if name.is_empty() {
            return Err(format!("--groups contains an empty entry in '{groups}'"));
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!(
                "--groups entry '{entry}' contains characters OpenSSL does not accept"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::TlsVersionArg;

    #[test]
    fn classifies_rfc10024_hybrids() {
        for g in RFC10024_HYBRID_GROUPS {
            assert_eq!(classify_group(g), KeyExchangeClass::HybridPq, "{g}");
            assert_eq!(classify_group(&g.to_lowercase()), KeyExchangeClass::HybridPq, "{g}");
        }
    }

    #[test]
    fn classifies_pure_obsolete_and_classical() {
        assert_eq!(classify_group("MLKEM768"), KeyExchangeClass::PurePq);
        assert_eq!(classify_group("X25519Kyber768Draft00"), KeyExchangeClass::ObsoletePq);
        assert_eq!(classify_group("X25519"), KeyExchangeClass::Classical);
        assert_eq!(classify_group("secp256r1"), KeyExchangeClass::Classical);
        assert_eq!(classify_group("prime256v1"), KeyExchangeClass::Classical);
        assert_eq!(classify_group("ffdhe2048"), KeyExchangeClass::Classical);
        assert_eq!(classify_group(""), KeyExchangeClass::Unknown);
        assert_eq!(classify_group("something-new"), KeyExchangeClass::Unknown);
        assert_eq!(classify_group("X448MLKEM1024"), KeyExchangeClass::HybridPq);
    }

    #[test]
    fn obsolete_groups_name_their_replacement() {
        assert_eq!(
            obsolete_group_replacement("X25519Kyber768Draft00"),
            Some("X25519MLKEM768 (RFC 10024)")
        );
        assert_eq!(obsolete_group_replacement("X25519MLKEM768"), None);
    }

    #[test]
    fn post_quantum_flag_matches_class() {
        assert!(KeyExchangeClass::HybridPq.is_post_quantum());
        assert!(KeyExchangeClass::PurePq.is_post_quantum());
        assert!(KeyExchangeClass::ObsoletePq.is_post_quantum());
        assert!(!KeyExchangeClass::Classical.is_post_quantum());
        assert!(!KeyExchangeClass::Unknown.is_post_quantum());
    }

    #[test]
    fn probe_groups_are_the_three_hybrids() {
        assert_eq!(pq_probe_groups(), "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024");
    }

    #[test]
    fn modern_profile_is_tls13_only_with_mlkem_first() {
        let s = TlsProfile::Modern.settings_for(true);
        assert_eq!(s.min_tls, TlsVersionArg::Tls1_3);
        assert!(s.cipher_list.is_none());
        assert!(s.cipher_suites.starts_with("TLS_AES_128_GCM_SHA256"));
        assert!(s.groups.starts_with("X25519MLKEM768:X25519"));
    }

    #[test]
    fn intermediate_profile_keeps_tls12_pfs_aead_only() {
        let s = TlsProfile::Intermediate.settings_for(false);
        assert_eq!(s.min_tls, TlsVersionArg::Tls1_2);
        let list = s.cipher_list.expect("cipher list");
        assert!(list.split(':').all(|c| c.starts_with("ECDHE-")));
        assert!(!list.split(':').any(|c| c.starts_with("DHE-")));
        assert!(!list.contains("CBC"));
        assert_eq!(s.groups, "X25519:prime256v1:secp384r1");
    }

    #[test]
    fn explicit_flags_win_over_profile() {
        let none = effective_tls_settings(None, None, None, None, None);
        assert_eq!(none, EffectiveTlsSettings::default());

        let modern = effective_tls_settings(Some(TlsProfile::Modern), None, None, None, None);
        assert_eq!(modern.min_tls, Some(TlsVersionArg::Tls1_3));
        assert!(modern.groups.is_some());

        let mixed = effective_tls_settings(
            Some(TlsProfile::Intermediate),
            Some(TlsVersionArg::Tls1_3),
            None,
            Some("TLS_AES_256_GCM_SHA384"),
            Some("X25519"),
        );
        assert_eq!(mixed.min_tls, Some(TlsVersionArg::Tls1_3));
        assert!(mixed.cipher_list.as_deref().is_some_and(|c| c.starts_with("ECDHE-")));
        assert_eq!(mixed.cipher_suites.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(mixed.groups.as_deref(), Some("X25519"));
    }

    #[test]
    fn group_list_validation() {
        assert!(validate_groups_list("X25519MLKEM768:X25519").is_ok());
        assert!(validate_groups_list("?*X25519MLKEM768 / ?*X25519:?secp256r1").is_ok());
        assert!(validate_groups_list("-X25519:DEFAULT").is_ok());
        assert!(validate_groups_list("").is_err());
        assert!(validate_groups_list("X25519::X448").is_err());
        assert!(validate_groups_list("X25519;rm -rf").is_err());
        assert!(validate_groups_list(&"X".repeat(2000)).is_err());
    }

    #[test]
    fn probe_results_carry_offered_groups() {
        let ok = PqProbeResult::supported("X25519MLKEM768".to_string());
        assert_eq!(ok.status, PqProbeStatus::Supported);
        assert_eq!(ok.offered.len(), 3);
        let no = PqProbeResult::not_supported("handshake failure");
        assert_eq!(no.status, PqProbeStatus::NotSupported);
        assert!(no.detail.contains("handshake failure"));
        let nt = PqProbeResult::not_testable();
        assert_eq!(nt.status, PqProbeStatus::NotTestable);
        assert!(nt.offered.is_empty());
    }

    #[test]
    fn openssl_summary_mentions_capability() {
        let s = openssl_summary();
        assert!(s.starts_with("OpenSSL") || s.starts_with("LibreSSL") || s.starts_with("BoringSSL"));
        assert!(s.contains("post quantum key exchange"));
    }
}
