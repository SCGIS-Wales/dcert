//! Cipher suites in every notation.
//!
//! One static table, generated from the IANA TLS Cipher Suites registry by
//! `scripts/gen_cipher_table.py`, gives each suite its code point, IANA name,
//! OpenSSL name and properties. [`Cipher::parse`] reads any single notation,
//! [`CipherSet::parse_list`] reads lists and OpenSSL keywords, and
//! [`Cipher::offerable`] says whether the linked OpenSSL can offer a suite.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::OnceLock;

use openssl::ssl::{Ssl, SslContext, SslMethod};
use serde::Serialize;

#[path = "ciphers_table.rs"]
mod table;

/// The protocol family a suite belongs to: TLS 1.3 suites (`0x13xx`) or
/// the suites of TLS 1.2 and earlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tls12,
    Tls13,
}

/// One cipher suite of the IANA registry.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Cipher {
    /// The two byte code point, `0xC02F` for `{0xC0,0x2F}`.
    pub code: u16,
    pub iana: &'static str,
    /// `None` when OpenSSL has no implementation of the suite.
    pub openssl: Option<&'static str>,
    pub protocol: Protocol,
    /// Key exchange, `any` for TLS 1.3.
    pub kx: &'static str,
    /// Authentication, `any` for TLS 1.3.
    pub au: &'static str,
    pub enc: &'static str,
    /// The MAC, or `AEAD` when the cipher authenticates.
    pub mac: &'static str,
    pub aead: bool,
    /// Forward secrecy: ephemeral key exchange, and every TLS 1.3 suite.
    pub pfs: bool,
    pub export: bool,
    pub null: bool,
    pub anonymous: bool,
    /// Approved for TLS under FIPS 140-3 (AES GCM or CCM with ECDHE or DHE
    /// and RSA or ECDSA, and the TLS 1.3 AES suites).
    pub fips: bool,
    /// Marked `Y` in the registry's Recommended column.
    pub recommended: bool,
    /// Marked `D` (discouraged) in the registry's Recommended column.
    pub discouraged: bool,
}

/// Why a cipher suite did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherParseError {
    Empty,
    /// A well formed code point that the registry does not assign.
    UnknownCodePoint(u16),
    /// No suite has this name; `suggestions` holds near misses.
    Unknown {
        input: String,
        suggestions: Vec<&'static str>,
    },
    /// OpenSSL rejected a keyword expression.
    Keyword {
        expression: String,
        reason: String,
    },
}

impl fmt::Display for CipherParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty cipher suite name"),
            Self::UnknownCodePoint(code) => write!(f, "no cipher suite is assigned code point 0x{code:04X}"),
            Self::Unknown { input, suggestions } => {
                write!(f, "unknown cipher suite `{input}`")?;
                if !suggestions.is_empty() {
                    write!(f, "; did you mean {}?", suggestions.join(" or "))?;
                }
                Ok(())
            }
            Self::Keyword { expression, reason } => {
                write!(f, "OpenSSL cannot expand cipher expression `{expression}`: {reason}")
            }
        }
    }
}

impl std::error::Error for CipherParseError {}

/// Every suite of the registry, in code point order.
pub fn all() -> &'static [Cipher] {
    table::CIPHERS
}

/// Upper case IANA and OpenSSL names to their suite.
fn by_name() -> &'static HashMap<String, &'static Cipher> {
    static INDEX: OnceLock<HashMap<String, &'static Cipher>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index = HashMap::new();
        for cipher in all() {
            index.insert(cipher.iana.to_ascii_uppercase(), cipher);
            if let Some(name) = cipher.openssl {
                index.entry(name.to_ascii_uppercase()).or_insert(cipher);
            }
        }
        index
    })
}

/// `0xC02F`, `C02F`, `0xC0,0x2F` (spaces and braces allowed) as a code point.
fn parse_code_point(input: &str) -> Option<u16> {
    let compact: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '{' | '}'))
        .collect();
    let lower = compact.to_ascii_lowercase();
    let hex = match lower.split_once(',') {
        Some((hi, lo)) => {
            let byte = |b: &str| {
                b.strip_prefix("0x")
                    .filter(|h| h.len() == 2 && h.bytes().all(|c| c.is_ascii_hexdigit()))
                    .map(str::to_string)
            };
            format!("{}{}", byte(hi)?, byte(lo)?)
        }
        None => lower.strip_prefix("0x").unwrap_or(&lower).to_string(),
    };
    if hex.len() != 4 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(&hex, 16).ok()
}

/// Edit distance between two ASCII strings, ignoring case.
fn levenshtein(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut row = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(!ca.eq_ignore_ascii_case(cb));
            row[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(row[j] + 1);
        }
        std::mem::swap(&mut prev, &mut row);
    }
    prev[b.len()]
}

/// Names within edit distance 2 of `input`, nearest first, at most three.
fn suggestions(input: &str) -> Vec<&'static str> {
    let mut near: Vec<(usize, &'static str)> = all()
        .iter()
        .flat_map(|c| std::iter::once(c.iana).chain(c.openssl))
        .map(|name| (levenshtein(input, name), name))
        .filter(|(distance, _)| *distance < 3)
        .collect();
    near.sort_unstable();
    near.dedup_by_key(|(_, name)| *name);
    near.into_iter().take(3).map(|(_, name)| name).collect()
}

impl Cipher {
    /// One suite from its IANA name, OpenSSL name or code point (`0xC02F`,
    /// `C02F`, `0xC0,0x2F`), case insensitive.
    pub fn parse(input: &str) -> Result<&'static Cipher, CipherParseError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(CipherParseError::Empty);
        }
        if let Some(code) = parse_code_point(input) {
            return Cipher::by_code(code).ok_or(CipherParseError::UnknownCodePoint(code));
        }
        by_name()
            .get(&input.to_ascii_uppercase())
            .copied()
            .ok_or_else(|| CipherParseError::Unknown {
                input: input.to_string(),
                suggestions: suggestions(input),
            })
    }

    /// The suite assigned `code`.
    pub fn by_code(code: u16) -> Option<&'static Cipher> {
        all().binary_search_by_key(&code, |c| c.code).ok().map(|i| &all()[i])
    }

    /// The code point as `0xC02F`.
    pub fn code_point(&self) -> String {
        format!("0x{:04X}", self.code)
    }

    /// Whether the linked OpenSSL can offer this suite at its default
    /// security level.
    pub fn offerable(&self) -> bool {
        offerable_codes().contains(&self.code)
    }
}

/// An ordered set of suites, split by protocol the way OpenSSL configures
/// them (a TLS 1.2 cipher list and a TLS 1.3 suite list).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CipherSet {
    pub tls12: Vec<&'static Cipher>,
    pub tls13: Vec<&'static Cipher>,
}

impl CipherSet {
    fn push(&mut self, cipher: &'static Cipher) {
        let list = match cipher.protocol {
            Protocol::Tls12 => &mut self.tls12,
            Protocol::Tls13 => &mut self.tls13,
        };
        if !list.iter().any(|c| c.code == cipher.code) {
            list.push(cipher);
        }
    }

    /// A colon or comma separated list of suites in any notation, OpenSSL
    /// keywords and operators included (`ECDHE+AESGCM`, `HIGH`, `!aNULL`).
    /// Keywords are expanded by the linked OpenSSL, in order.
    pub fn parse_list(input: &str) -> Result<CipherSet, CipherParseError> {
        let tokens = tokens(input);
        if tokens.is_empty() {
            return Err(CipherParseError::Empty);
        }
        let mut set = CipherSet::default();
        let mut expression: Vec<String> = Vec::new();
        let mut keywords = false;
        for token in &tokens {
            match Cipher::parse(token) {
                Ok(cipher) => {
                    set.push(cipher);
                    if let (Protocol::Tls12, Some(name)) = (cipher.protocol, cipher.openssl) {
                        expression.push(name.to_string());
                    }
                }
                Err(_) if is_keyword(token) => {
                    keywords = true;
                    expression.push(token.clone());
                }
                Err(err) => return Err(err),
            }
        }
        if keywords {
            // OpenSSL decides the TLS 1.2 list and its order.
            set.tls12 = expand(&expression.join(":"))?;
        }
        Ok(set)
    }

    /// The TLS 1.2 list in OpenSSL notation, for `set_cipher_list`; suites
    /// OpenSSL does not implement are left out.
    pub fn cipher_list(&self) -> Option<String> {
        join_openssl(&self.tls12)
    }

    /// The TLS 1.3 list, for `set_ciphersuites`.
    pub fn ciphersuites(&self) -> Option<String> {
        join_openssl(&self.tls13)
    }
}

fn join_openssl(ciphers: &[&'static Cipher]) -> Option<String> {
    let names: Vec<&str> = ciphers.iter().filter_map(|c| c.openssl).collect();
    (!names.is_empty()).then(|| names.join(":"))
}

/// Split on `:` and `,`, rejoining `0xC0,0x2F` pairs and dropping blanks.
fn tokens(input: &str) -> Vec<String> {
    let is_byte = |t: &str| {
        let t = t.trim().to_ascii_lowercase();
        t.len() == 4 && t.starts_with("0x") && t[2..].bytes().all(|c| c.is_ascii_hexdigit())
    };
    let raw: Vec<&str> = input.split([':', ',']).map(str::trim).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if is_byte(raw[i]) && raw.get(i + 1).is_some_and(|next| is_byte(next)) {
            out.push(format!("{},{}", raw[i], raw[i + 1]));
            i += 2;
        } else {
            if !raw[i].is_empty() {
                out.push(raw[i].to_string());
            }
            i += 1;
        }
    }
    out
}

/// An OpenSSL cipher string element rather than a suite name: an operator
/// (`!`, `-`, `+`, `@`), a `+` combination, or a word OpenSSL matches to at
/// least one cipher (`HIGH`, `aNULL`, `ECDHE`). A misspelt suite name is none
/// of these, so it is reported with suggestions instead of ignored.
fn is_keyword(token: &str) -> bool {
    if token.starts_with(['!', '-', '+', '@']) || token.contains('+') {
        return true;
    }
    expand(token).is_ok_and(|ciphers| !ciphers.is_empty())
}

/// The TLS 1.2 suites an OpenSSL cipher string selects, in its order.
fn expand(expression: &str) -> Result<Vec<&'static Cipher>, CipherParseError> {
    let keyword_error = |reason: String| CipherParseError::Keyword {
        expression: expression.to_string(),
        reason,
    };
    let mut builder = SslContext::builder(SslMethod::tls()).map_err(|e| keyword_error(e.to_string()))?;
    builder
        .set_cipher_list(expression)
        .map_err(|e| keyword_error(e.to_string()))?;
    let ssl = Ssl::new(&builder.build()).map_err(|e| keyword_error(e.to_string()))?;
    let mut set = CipherSet::default();
    for code in ffi::configured_ciphers(&ssl) {
        if let Some(cipher) = Cipher::by_code(code) {
            set.push(cipher);
        }
    }
    Ok(set.tls12)
}

/// Code points the linked OpenSSL offers when every cipher is enabled, at
/// the library's default security level. Computed once.
fn offerable_codes() -> &'static HashSet<u16> {
    static CODES: OnceLock<HashSet<u16>> = OnceLock::new();
    CODES.get_or_init(|| {
        let build = || -> Result<HashSet<u16>, openssl::error::ErrorStack> {
            let mut builder = SslContext::builder(SslMethod::tls_client())?;
            builder.set_cipher_list("ALL:COMPLEMENTOFALL")?;
            let suites: Vec<&str> = all()
                .iter()
                .filter(|c| c.protocol == Protocol::Tls13)
                .filter_map(|c| c.openssl)
                .collect();
            // Unknown names are skipped by OpenSSL as long as one is valid.
            builder.set_ciphersuites(&suites.join(":"))?;
            let ssl = Ssl::new(&builder.build())?;
            Ok(ffi::supported_ciphers(&ssl).into_iter().collect())
        };
        build().unwrap_or_default()
    })
}

/// The two libssl cipher list entry points the openssl crate does not wrap.
/// Both exist since OpenSSL 1.1.0.
#[allow(unsafe_code)]
mod ffi {
    use foreign_types::{ForeignType, ForeignTypeRef};
    use openssl::ssl::{SslCipher, SslRef};
    use openssl::stack::{Stack, StackRef};

    unsafe extern "C" {
        fn SSL_get_ciphers(ssl: *const openssl_sys::SSL) -> *mut openssl_sys::stack_st_SSL_CIPHER;
        fn SSL_get1_supported_ciphers(ssl: *mut openssl_sys::SSL) -> *mut openssl_sys::stack_st_SSL_CIPHER;
    }

    fn code(cipher: &openssl::ssl::SslCipherRef) -> u16 {
        u16::from_be_bytes(cipher.protocol_id())
    }

    /// The ciphers configured on `ssl`, in preference order.
    pub(super) fn configured_ciphers(ssl: &SslRef) -> Vec<u16> {
        // SAFETY: `ssl` is a live SSL handle. SSL_get_ciphers returns a stack
        // owned by it (or null), borrowed only while `ssl` is borrowed here.
        let list = unsafe { SSL_get_ciphers(ssl.as_ptr()) };
        if list.is_null() {
            return Vec::new();
        }
        // SAFETY: non null STACK_OF(SSL_CIPHER) owned by `ssl`.
        let stack: &StackRef<SslCipher> = unsafe { StackRef::from_ptr(list) };
        stack.iter().map(code).collect()
    }

    /// The ciphers `ssl` would offer: configured, available and allowed by
    /// the version range and security level.
    pub(super) fn supported_ciphers(ssl: &SslRef) -> Vec<u16> {
        // SAFETY: `ssl` is a live SSL handle. SSL_get1_supported_ciphers
        // returns a new stack (or null) that the caller frees; the ciphers in
        // it are static, and SslCipher's drop does not free them.
        let list = unsafe { SSL_get1_supported_ciphers(ssl.as_ptr()) };
        if list.is_null() {
            return Vec::new();
        }
        // SAFETY: the stack is ours; Stack frees it (not its ciphers) on drop.
        let stack: Stack<SslCipher> = unsafe { Stack::from_ptr(list) };
        stack.iter().map(code).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The four TLS 1.2 ciphers and three TLS 1.3 suites of the AWS ALB
    /// policy `ELBSecurityPolicy-TLS13-1-2-2021-06`.
    const ALB: &[(u16, &str, &str)] = &[
        (
            0xC02B,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
        ),
        (
            0xC02F,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ),
        (
            0xC02C,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
        ),
        (
            0xC030,
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ),
        (0x1301, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"),
        (0x1302, "TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"),
        (0x1303, "TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256"),
    ];

    #[test]
    fn the_table_is_sorted_and_unique() {
        assert!(all().windows(2).all(|w| w[0].code < w[1].code));
        assert!(!all().is_empty());
    }

    #[test]
    fn every_row_round_trips_iana_to_openssl_to_code_point() {
        for cipher in all() {
            assert_eq!(Cipher::parse(cipher.iana).unwrap().code, cipher.code, "{}", cipher.iana);
            if let Some(name) = cipher.openssl {
                assert_eq!(Cipher::parse(name).unwrap().code, cipher.code, "{name}");
            }
            assert_eq!(Cipher::parse(&cipher.code_point()).unwrap().code, cipher.code);
        }
    }

    #[test]
    fn the_alb_suites_parse_from_every_notation() {
        for &(code, iana, openssl) in ALB {
            let hi = code >> 8;
            let lo = code & 0xFF;
            let notations = [
                iana.to_string(),
                iana.to_ascii_lowercase(),
                openssl.to_string(),
                openssl.to_ascii_lowercase(),
                format!("0x{code:04X}"),
                format!("0x{code:04x}"),
                format!("{code:04X}"),
                format!("0x{hi:02X},0x{lo:02X}"),
                format!("{{0x{hi:02X}, 0x{lo:02X}}}"),
            ];
            for notation in &notations {
                let cipher = Cipher::parse(notation).unwrap_or_else(|e| panic!("{notation}: {e}"));
                assert_eq!((cipher.code, cipher.iana, cipher.openssl), (code, iana, Some(openssl)));
            }
        }
    }

    #[test]
    fn alb_properties() {
        let c = Cipher::parse("C02F").unwrap();
        assert_eq!(
            (c.protocol, c.kx, c.au, c.enc, c.mac),
            (Protocol::Tls12, "ECDHE", "RSA", "AES_128_GCM", "AEAD")
        );
        assert!(c.aead && c.pfs && c.fips && !c.null && !c.export && !c.anonymous);
        let t = Cipher::parse("TLS_CHACHA20_POLY1305_SHA256").unwrap();
        assert_eq!(t.protocol, Protocol::Tls13);
        assert!(t.aead && t.pfs && !t.fips);
    }

    #[test]
    fn unknown_names_suggest_near_misses() {
        let err = Cipher::parse("ECDHE-RSA-AES128-GCM-SHA265").unwrap_err();
        let CipherParseError::Unknown { suggestions, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(suggestions.first(), Some(&"ECDHE-RSA-AES128-GCM-SHA256"));
        assert!(err.to_string().contains("did you mean ECDHE-RSA-AES128-GCM-SHA256"));
        let far = Cipher::parse("NOT-A-CIPHER-AT-ALL").unwrap_err();
        assert_eq!(far.to_string(), "unknown cipher suite `NOT-A-CIPHER-AT-ALL`");
    }

    #[test]
    fn code_points_must_be_assigned_and_well_formed() {
        assert_eq!(Cipher::parse("0xFFFF"), Err(CipherParseError::UnknownCodePoint(0xFFFF)));
        assert_eq!(Cipher::parse(" "), Err(CipherParseError::Empty));
        assert!(matches!(
            Cipher::parse("0xC0,0x2"),
            Err(CipherParseError::Unknown { .. })
        ));
        assert_eq!(parse_code_point("0xC0,0x2F"), Some(0xC02F));
        assert_eq!(parse_code_point("c02f"), Some(0xC02F));
        assert_eq!(parse_code_point("0xC02F0"), None);
    }

    #[test]
    fn levenshtein_distances() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("ABC", "abc"), 0);
    }

    #[test]
    fn lists_split_by_protocol_and_keep_order() {
        let set =
            CipherSet::parse_list("0xC0,0x2F:TLS_AES_256_GCM_SHA384, ecdhe-ecdsa-aes128-gcm-sha256,1301").unwrap();
        let codes = |v: &[&Cipher]| v.iter().map(|c| c.code).collect::<Vec<_>>();
        assert_eq!(codes(&set.tls12), [0xC02F, 0xC02B]);
        assert_eq!(codes(&set.tls13), [0x1302, 0x1301]);
        assert_eq!(
            set.cipher_list().as_deref(),
            Some("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256")
        );
        assert_eq!(
            set.ciphersuites().as_deref(),
            Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")
        );
    }

    #[test]
    fn duplicates_collapse() {
        let set =
            CipherSet::parse_list("C02F,ECDHE-RSA-AES128-GCM-SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").unwrap();
        assert_eq!(set.tls12.len(), 1);
    }

    #[test]
    fn keywords_expand_through_openssl() {
        let set = CipherSet::parse_list("ECDHE+AESGCM:!aNULL").unwrap();
        assert!(set.tls12.iter().any(|c| c.code == 0xC02F), "{set:?}");
        assert!(set.tls12.iter().all(|c| c.kx == "ECDHE" && c.aead && !c.anonymous));
        assert!(set.tls13.is_empty());
        let high = CipherSet::parse_list("HIGH").unwrap();
        assert!(!high.tls12.is_empty());
    }

    #[test]
    fn a_misspelt_name_in_a_list_is_an_error_not_a_keyword() {
        let err = CipherSet::parse_list("HIGH:ECDHE-RSA-AES128-GCM-SHA265").unwrap_err();
        assert!(matches!(err, CipherParseError::Unknown { .. }), "{err:?}");
        assert_eq!(CipherSet::parse_list(" : , "), Err(CipherParseError::Empty));
    }

    #[test]
    fn the_linked_openssl_offers_the_alb_suites() {
        for &(code, iana, _) in ALB {
            assert!(Cipher::by_code(code).unwrap().offerable(), "{iana}");
        }
        assert!(!Cipher::parse("TLS_NULL_WITH_NULL_NULL").unwrap().offerable());
    }
}
