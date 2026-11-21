//! Which TLS root stores include a root: Mozilla, Chrome, Apple, Microsoft.
//!
//! Built from the CCADB TLS server authentication reports by
//! `scripts/gen_root_stores.py` (`src/trust_anchors/root_stores.json`,
//! CDLA-Permissive-2.0, attribution in `src/trust_anchors/NOTICE`). Roots are
//! looked up by certificate SHA-256 and, for reissued or cross-signed copies
//! of the same key, by SPKI SHA-256. Store limits that depend on the leaf
//! (Mozilla's and Chrome's distrust-after dates) are evaluated against the
//! leaf's notBefore.

use std::collections::HashMap;
use std::sync::OnceLock;

use openssl::hash::MessageDigest;
use openssl::x509::X509Ref;
use serde::Deserialize;

const INDEX: &str = include_str!("trust_anchors/root_stores.json");

/// One root of the index.
#[derive(Debug, Clone, Deserialize)]
pub struct StoreEntry {
    pub sha256: String,
    pub spki_sha256: String,
    pub name: String,
    pub owner: String,
    /// The stores that include this root (`mozilla`, `chrome`, `apple`,
    /// `microsoft`).
    pub stores: Vec<String>,
    #[serde(default)]
    pub limits: HashMap<String, Limits>,
}

/// Per store limits on TLS trust, as CCADB reports them.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Limits {
    /// Mozilla: certificates issued after this date (`M/D/YYYY`) are distrusted.
    pub distrust_after: Option<String>,
    /// Chrome: certificates whose SCTs are later than this are distrusted.
    pub distrust_after_unix: Option<i64>,
    /// Chrome: the root may only issue for these DNS names.
    pub permitted_dns_names: Option<String>,
    /// Apple: the purposes the root is constrained to.
    pub constraints: Option<String>,
    /// Microsoft: the root is disabled from this date.
    pub disabled: Option<String>,
}

#[derive(Deserialize)]
struct Index {
    roots: Vec<StoreEntry>,
}

struct Lookup {
    by_cert: HashMap<String, usize>,
    by_key: HashMap<String, Vec<usize>>,
    roots: Vec<StoreEntry>,
}

fn lookup_table() -> &'static Lookup {
    static TABLE: OnceLock<Lookup> = OnceLock::new();
    TABLE.get_or_init(|| {
        let roots = serde_json::from_str::<Index>(INDEX)
            .map(|i| i.roots)
            .unwrap_or_default();
        let mut by_cert = HashMap::new();
        let mut by_key: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, root) in roots.iter().enumerate() {
            by_cert.insert(root.sha256.clone(), i);
            by_key.entry(root.spki_sha256.clone()).or_default().push(i);
        }
        Lookup { by_cert, by_key, roots }
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// The stores that include `root`: by its certificate, else the union of the
/// entries that share its key. `None` when no store includes it.
pub fn stores_of(root: &X509Ref) -> Option<(Vec<String>, Vec<&'static StoreEntry>)> {
    let table = lookup_table();
    let sha = hex(&root.digest(MessageDigest::sha256()).ok()?);
    let entries: Vec<&'static StoreEntry> = if let Some(&i) = table.by_cert.get(&sha) {
        vec![&table.roots[i]]
    } else {
        let spki = root.public_key().ok()?.public_key_to_der().ok()?;
        let key = hex(&openssl::sha::sha256(&spki));
        table.by_key.get(&key)?.iter().map(|&i| &table.roots[i]).collect()
    };
    let mut stores: Vec<String> = Vec::new();
    for store in ["mozilla", "chrome", "apple", "microsoft"] {
        if entries.iter().any(|e| e.stores.iter().any(|s| s == store)) {
            stores.push(store.to_string());
        }
    }
    (!stores.is_empty()).then_some((stores, entries))
}

/// `M/D/YYYY` as a Unix time at 00:00 UTC.
fn us_date(text: &str) -> Option<i64> {
    let mut parts = text.split('/').map(|p| p.trim().parse::<i64>());
    let (m, d, y) = (parts.next()?.ok()?, parts.next()?.ok()?, parts.next()?.ok()?);
    let month = time::Month::try_from(u8::try_from(m).ok()?).ok()?;
    let date = time::Date::from_calendar_date(i32::try_from(y).ok()?, month, u8::try_from(d).ok()?).ok()?;
    Some(date.midnight().assume_utc().unix_timestamp())
}

/// The stores that trust a leaf issued at `leaf_not_before` (Unix time) under
/// a root in `entries`, and one note per store whose limit excludes it.
pub fn trusting(
    stores: &[String],
    entries: &[&StoreEntry],
    leaf_not_before: Option<i64>,
) -> (Vec<String>, Vec<String>) {
    let mut trusted = Vec::new();
    let mut notes = Vec::new();
    for store in stores {
        let limit = entries.iter().find_map(|e| e.limits.get(store));
        let cutoff = limit.and_then(|l| match store.as_str() {
            "mozilla" => l.distrust_after.as_deref().and_then(us_date),
            "chrome" => l.distrust_after_unix,
            _ => None,
        });
        match (cutoff, leaf_not_before) {
            (Some(cutoff), Some(issued)) if issued > cutoff => {
                let day = time::OffsetDateTime::from_unix_timestamp(cutoff)
                    .map(|t| t.date().to_string())
                    .unwrap_or_default();
                notes.push(format!(
                    "{store} distrusts certificates from this root issued after {day}"
                ));
            }
            _ => trusted.push(store.clone()),
        }
    }
    (trusted, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_parses_and_covers_the_four_stores() {
        let table = lookup_table();
        assert!(table.roots.len() > 150);
        for store in ["mozilla", "chrome", "apple", "microsoft"] {
            assert!(
                table.roots.iter().any(|r| r.stores.iter().any(|s| s == store)),
                "{store}"
            );
        }
    }

    #[test]
    fn us_dates() {
        assert_eq!(us_date("1/1/1970"), Some(0));
        assert_eq!(us_date("8/6/2026"), Some(1_785_974_400));
        assert_eq!(us_date("nonsense"), None);
    }

    #[test]
    fn a_distrust_after_date_drops_the_store_for_later_leaves() {
        let entry = StoreEntry {
            sha256: String::new(),
            spki_sha256: String::new(),
            name: "Example".into(),
            owner: "Example".into(),
            stores: vec!["chrome".into(), "apple".into()],
            limits: HashMap::from([(
                "chrome".to_string(),
                Limits {
                    distrust_after_unix: Some(1_000),
                    ..Limits::default()
                },
            )]),
        };
        let stores = entry.stores.clone();
        let (trusted, notes) = trusting(&stores, &[&entry], Some(2_000));
        assert_eq!(trusted, vec!["apple".to_string()]);
        assert!(notes[0].starts_with("chrome distrusts"));
        let (trusted, notes) = trusting(&stores, &[&entry], Some(500));
        assert_eq!(trusted.len(), 2);
        assert!(notes.is_empty());
    }
}
