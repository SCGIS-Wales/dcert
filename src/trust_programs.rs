//! Trust programs other than Mozilla's website (TLS server) root set.
//!
//! `webpki-root-certs` holds only the roots Mozilla trusts for websites, so a
//! chain anchored on a publicly operated root for another purpose used to be
//! reported as private PKI. The programs here are recognised by the same
//! offline signature check as the Mozilla set (never by name), and only for
//! classification: dcert never trusts them for a TLS connection.
//!
//! Sources, fingerprints and the generator live in `scripts/trust_anchors.yaml`
//! and `scripts/gen_trust_anchors.py`.

use openssl::x509::X509;

/// What a trust program vouches for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// TLS server authentication (websites).
    ServerAuth,
    /// Email protection (S/MIME); certificates from these roots also serve
    /// client authentication in some deployments.
    Email,
    /// Mutual TLS between members of an industry PKI.
    IndustryMtls,
    /// A cloud provider's CA for its own managed service endpoints.
    CloudService,
}

/// One embedded certificate of a trust program.
#[derive(Debug, Clone, Copy)]
pub struct Anchor {
    pub name: &'static str,
    pub pem: &'static str,
    /// SHA-256 of the DER as published by the operator (upper case hex).
    pub sha256: &'static str,
    /// A root (trust anchor) or an intermediate that only completes chains.
    pub root: bool,
    /// Preproduction (test) hierarchy.
    pub preproduction: bool,
}

/// A trust program: who operates it, what it is for and its anchors.
#[derive(Debug, Clone, Copy)]
pub struct Program {
    /// Stable identifier, reported as `root_trust.trust_program`.
    pub id: &'static str,
    pub name: &'static str,
    pub operator: &'static str,
    pub purpose: Purpose,
    /// Whether browsers trust the program's roots for websites.
    pub browser_trusted: bool,
    pub anchors: &'static [Anchor],
    /// A PEM bundle of roots (all `root`, none preproduction), for programs
    /// generated from a root store rather than listed one by one.
    pub bundle: Option<&'static str>,
}

macro_rules! x9 {
    ($file:literal, $sha:literal, $root:expr, $pre:expr) => {
        Anchor {
            name: $file,
            pem: include_str!(concat!("trust_anchors/x9/", $file, ".pem")),
            sha256: $sha,
            root: $root,
            preproduction: $pre,
        }
    };
}

/// The X9 Financial PKI (ASC X9 certificate policy, operated by DigiCert).
pub const X9_ANCHORS: &[Anchor] = &[
    x9!(
        "X9FinancialPKIECCP256Root",
        "D9DE4153E4336D7E481E3152575721BD0D36A7ABAF4DB861473BB76451E50936",
        true,
        false
    ),
    x9!(
        "X9FinancialPKIRSA2048Root",
        "49B62A0249E48FEE51682DE5C152E4BE03C774532B79A5D81F2F408DA5850263",
        true,
        false
    ),
    x9!(
        "X9FinancialPKIRSA4096Root",
        "A4C1515606CD7E010F5158CC88CF8B03C35CD4D8080D283F56CCEABD924CDAB5",
        true,
        false
    ),
    x9!(
        "X9FinancialPKI-RSA4096ICA-1",
        "674D91CB7B97A3C19F9B3ABC832710B17C21E7416FAD74CB3F715DDBAF050DC5",
        false,
        false
    ),
    x9!(
        "X9FinancialPKI-RSA4096ICAEU-1",
        "B2850B71353A785539D84578B3935DD4267AB07C1E68D769B66669D05374DBBB",
        false,
        false
    ),
    x9!(
        "X9FinancialPKIECCP256RootUAT",
        "37E76B622A446680D175533A1A4920330DD7F608001E568EEA824D8818C0D299",
        true,
        true
    ),
    x9!(
        "X9FinancialPKIRSA2048RootUAT",
        "061B0149E4CC58B87FA85211B8EB472FB599CB0E05A39F3818B396C98C33A0F8",
        true,
        true
    ),
    x9!(
        "X9FinancialPKIRSA4096RootUAT",
        "3FEA4F45787FE5AE4A2ED4E8E3D63B69D7F91BCF90B13447168F36DF800AC83E",
        true,
        true
    ),
    x9!(
        "X9FinancialPKI-MLDSA-87Root-UAT",
        "78937B264BC9257E1229EB32B77C088E1244AF9D161B40EAA468FC85F2AE3D60",
        true,
        true
    ),
    x9!(
        "X9FinancialPKI-MLDSA-65Root-UAT",
        "E16FFEEF4BB2BD65AE0622E5AF20B00B8E68008A8B2CC5802A3EA47E77A58903",
        true,
        true
    ),
    x9!(
        "X9FinancialPKI-MLDSA-44Root-UAT",
        "393A1C2F6441DBF4D465465F655BC8B97DC8733313E7D4BA018F3B1501717556",
        true,
        true
    ),
];

/// Roots Mozilla trusts for email and not for websites (generated).
pub const MOZILLA_EMAIL_BUNDLE: &str = include_str!("trust_anchors/mozilla_email.pem");

/// Roots of the Chrome, Apple or Microsoft TLS stores that Mozilla does not
/// include (generated from CCADB, see `src/trust_anchors/NOTICE`).
pub const OTHER_STORES_BUNDLE: &str = include_str!("trust_anchors/root_stores.pem");

/// The Amazon RDS (Aurora, DocumentDB, Neptune) regional database CA roots.
pub const AWS_RDS_BUNDLE: &str = include_str!("trust_anchors/aws_rds.pem");

/// The programs tried, in order, after the Mozilla website set.
pub const PROGRAMS: &[Program] = &[
    // Before the email set: a root Mozilla trusts for email only may still be
    // a TLS root of another store (DigiCert Global Root CA, GTS Root R2).
    Program {
        id: "other_root_stores",
        name: "Chrome, Apple or Microsoft TLS root store",
        operator: "Chrome, Apple or Microsoft root program (CCADB)",
        purpose: Purpose::ServerAuth,
        browser_trusted: true,
        anchors: &[],
        bundle: Some(OTHER_STORES_BUNDLE),
    },
    Program {
        id: "mozilla_email",
        name: "Mozilla email (S/MIME) root store",
        operator: "Mozilla root program (CCADB)",
        purpose: Purpose::Email,
        browser_trusted: false,
        anchors: &[],
        bundle: Some(MOZILLA_EMAIL_BUNDLE),
    },
    Program {
        id: "x9_financial",
        name: "X9 Financial PKI",
        operator: "DigiCert, under the ASC X9 certificate policy",
        purpose: Purpose::IndustryMtls,
        browser_trusted: false,
        anchors: X9_ANCHORS,
        bundle: None,
    },
    Program {
        id: "aws_rds",
        name: "Amazon RDS certificate authority",
        operator: "Amazon Web Services (RDS, Aurora, DocumentDB, Neptune)",
        purpose: Purpose::CloudService,
        browser_trusted: false,
        anchors: &[],
        bundle: Some(AWS_RDS_BUNDLE),
    },
];

/// The certificates of `program` as `(certificate, anchor)`. A certificate
/// OpenSSL cannot parse (an ML-DSA root on OpenSSL before 3.5) is skipped.
pub fn certificates(program: &Program) -> Vec<(X509, Option<&'static Anchor>)> {
    let mut out: Vec<(X509, Option<&'static Anchor>)> = program
        .anchors
        .iter()
        .filter_map(|a| X509::from_pem(a.pem.as_bytes()).ok().map(|c| (c, Some(a))))
        .collect();
    if let Some(bundle) = program.bundle
        && let Ok(stack) = X509::stack_from_pem(bundle.as_bytes())
    {
        out.extend(stack.into_iter().map(|c| (c, None)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::hash::MessageDigest;

    fn sha256_hex(cert: &X509) -> String {
        cert.digest(MessageDigest::sha256())
            .expect("digest")
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    }

    #[test]
    fn every_parseable_x9_anchor_matches_its_published_fingerprint() {
        let mut checked = 0;
        for anchor in X9_ANCHORS {
            match X509::from_pem(anchor.pem.as_bytes()) {
                Ok(cert) => {
                    assert_eq!(sha256_hex(&cert), anchor.sha256, "{}", anchor.name);
                    checked += 1;
                }
                // Only the ML-DSA roots may fail, on OpenSSL before 3.5.
                Err(_) => assert!(anchor.name.contains("MLDSA"), "{} does not parse", anchor.name),
            }
        }
        assert!(checked >= 8, "the RSA and ECC anchors always parse");
    }

    #[test]
    fn x9_production_roots_and_intermediates() {
        let production: Vec<_> = X9_ANCHORS.iter().filter(|a| !a.preproduction).collect();
        assert_eq!(production.iter().filter(|a| a.root).count(), 3);
        assert_eq!(production.iter().filter(|a| !a.root).count(), 2);
    }

    #[test]
    fn email_bundle_holds_the_sectigo_and_digicert_smime_roots() {
        let names: Vec<String> = X509::stack_from_pem(MOZILLA_EMAIL_BUNDLE.as_bytes())
            .expect("bundle parses")
            .iter()
            .filter_map(|c| {
                c.subject_name()
                    .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                    .next()
                    .and_then(|e| e.data().to_string().ok())
            })
            .collect();
        for expected in [
            "Sectigo Public Email Protection Root R46",
            "Sectigo Public Email Protection Root E46",
            "DigiCert SMIME RSA4096 Root G5",
        ] {
            assert!(names.iter().any(|n| n == expected), "{expected} missing");
        }
        // Website roots are in webpki-root-certs, not here.
        assert!(
            !names
                .iter()
                .any(|n| n == "Sectigo Public Server Authentication Root R46")
        );
    }

    #[test]
    fn only_the_other_root_stores_are_browser_trusted() {
        assert!(
            PROGRAMS
                .iter()
                .all(|p| p.browser_trusted == (p.id == "other_root_stores"))
        );
        assert!(PROGRAMS.iter().all(|p| !certificates(p).is_empty()));
    }
}
