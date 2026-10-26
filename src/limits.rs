//! Defaults and accepted ranges for numeric options, defined once.
//!
//! The CLI's clap parsers and the MCP server's parameter checks both read
//! these, so a value one surface accepts is never refused by the other.

use std::ops::RangeInclusive;

/// `--timeout`: TCP connect timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
/// Accepted `--timeout` values.
pub const TIMEOUT_RANGE: RangeInclusive<u64> = 1..=300;

/// `--read-timeout`: per read timeout in seconds.
pub const DEFAULT_READ_TIMEOUT_SECS: u64 = 5;
/// Accepted `--read-timeout` values.
pub const READ_TIMEOUT_RANGE: RangeInclusive<u64> = 1..=300;

/// `--issuer-timeout`: AIA issuer fetch timeout in seconds.
pub const DEFAULT_ISSUER_TIMEOUT_SECS: u64 = 2;
/// Accepted `--issuer-timeout` values.
pub const ISSUER_TIMEOUT_RANGE: RangeInclusive<u64> = 1..=60;

/// Accepted `--watch` intervals in seconds (one second to one day).
pub const WATCH_RANGE: RangeInclusive<u64> = 1..=86_400;

/// `--body-limit`: response body bytes kept as evidence.
pub const DEFAULT_BODY_LIMIT: usize = 16 * 1024;
/// Largest `--body-limit`.
pub const MAX_BODY_LIMIT: usize = 1024 * 1024;
const _: () = assert!(DEFAULT_BODY_LIMIT <= MAX_BODY_LIMIT);

/// `dcert tls-scan --max-handshakes`: handshakes one scan may make.
pub const DEFAULT_MAX_HANDSHAKES: u64 = 120;
/// Accepted `--max-handshakes` values.
pub const MAX_HANDSHAKES_RANGE: RangeInclusive<u64> = 1..=2_000;
/// Handshakes a scan runs at once, so a server is not flooded.
pub const SCAN_CONCURRENCY: usize = 4;

/// `DCERT_MCP_TIMEOUT`: subprocess timeout in seconds for the MCP server.
pub const SUBPROCESS_TIMEOUT_RANGE: RangeInclusive<u64> = 1..=3600;

/// `--expiry-warn` and the MCP `check_expiry.days` default, in days.
pub const DEFAULT_EXPIRY_WARN_DAYS: u64 = 30;
/// Accepted `--expiry-warn` values (up to one hundred years).
pub const EXPIRY_WARN_RANGE: RangeInclusive<u64> = 0..=36_500;

/// Directory converted PEM files are written to when none is given.
pub const DEFAULT_OUTPUT_DIR: &str = ".";
/// Alias of the key entry in a new PKCS12 keystore.
pub const DEFAULT_KEYSTORE_ALIAS: &str = "server";
/// Password of a new PKCS12 truststore (the Java convention).
pub const DEFAULT_TRUSTSTORE_PASSWORD: &str = "changeit";

/// Vault certificate TTL.
pub const DEFAULT_VAULT_TTL: &str = "8760h";
/// Vault PKI secrets engine mount.
pub const DEFAULT_VAULT_PKI_MOUNT: &str = "vault_intermediate";
/// Vault authentication method.
pub const DEFAULT_VAULT_AUTH_METHOD: &str = "token";
/// Vault LDAP auth mount.
pub const DEFAULT_VAULT_LDAP_MOUNT: &str = "ldap";
/// Vault AppRole auth mount.
pub const DEFAULT_VAULT_APPROLE_MOUNT: &str = "approle";
/// Vault KV secrets engine version.
pub const DEFAULT_KV_VERSION: u8 = 1;
/// Accepted Vault KV versions.
pub const KV_VERSION_RANGE: RangeInclusive<u8> = 1..=2;
/// Field of a Vault KV secret that holds the certificate.
pub const DEFAULT_KV_CERT_KEY: &str = "cert";
/// Field of a Vault KV secret that holds the private key.
pub const DEFAULT_KV_KEY_KEY: &str = "key";

/// Check `value` against `range`, naming the option in the error.
pub fn check_range(name: &str, value: u64, range: &RangeInclusive<u64>) -> Result<u64, String> {
    if range.contains(&value) {
        Ok(value)
    } else {
        Err(format!(
            "{name} must be between {} and {}, got {value}",
            range.start(),
            range.end()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_range_accepts_the_bounds_and_names_the_option() {
        assert_eq!(check_range("--timeout", 1, &TIMEOUT_RANGE), Ok(1));
        assert_eq!(check_range("--timeout", 300, &TIMEOUT_RANGE), Ok(300));
        let err = check_range("--timeout", 0, &TIMEOUT_RANGE).expect_err("zero");
        assert!(err.contains("--timeout") && err.contains("between 1 and 300"), "{err}");
        assert!(check_range("--watch", 86_401, &WATCH_RANGE).is_err());
        assert!(EXPIRY_WARN_RANGE.contains(&DEFAULT_EXPIRY_WARN_DAYS));
        assert!(KV_VERSION_RANGE.contains(&DEFAULT_KV_VERSION));
    }

    #[test]
    fn defaults_lie_inside_their_ranges() {
        assert!(TIMEOUT_RANGE.contains(&DEFAULT_TIMEOUT_SECS));
        assert!(READ_TIMEOUT_RANGE.contains(&DEFAULT_READ_TIMEOUT_SECS));
        assert!(ISSUER_TIMEOUT_RANGE.contains(&DEFAULT_ISSUER_TIMEOUT_SECS));
        assert!(MAX_HANDSHAKES_RANGE.contains(&DEFAULT_MAX_HANDSHAKES));
    }
}
