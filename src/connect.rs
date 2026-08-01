//! Connection overrides — curl-compatible `--resolve` and `--connect-to`.
//!
//! These let a caller redirect where dcert actually dials while keeping the
//! target hostname for SNI, the HTTP `Host:` header and certificate validation.
//! That is the difference from `--sni`, which changes the validated identity.
//!
//! Two spellings, matching curl:
//!
//! * `--resolve HOST:PORT:ADDR[,ADDR...]` — pin a host/port pair to one or more
//!   IP **addresses**. Hostnames are rejected here, as in curl.
//! * `--connect-to HOST1:PORT1:HOST2:PORT2` — redirect to another host *or* IP,
//!   optionally on a different port. Empty fields mean "any"/"unchanged".
//!
//! dcert also keeps its original single-value `--connect-to <IP>` spelling,
//! which is equivalent to `--connect-to ::<IP>:`.
//!
//! Both flags are repeatable and share one lookup table; the first entry whose
//! host and port match wins, as in curl.

use std::fmt;
use std::net::IpAddr;

/// Which flag an override came from — used for diagnostics only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideSource {
    Resolve,
    ConnectTo,
}

impl fmt::Display for OverrideSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OverrideSource::Resolve => f.write_str("--resolve"),
            OverrideSource::ConnectTo => f.write_str("--connect-to"),
        }
    }
}

/// A single parsed override entry.
///
/// Constructed by [`parse_resolve`] / [`parse_connect_to`], which double as clap
/// `value_parser`s so malformed values are rejected during argument parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectOverride {
    /// Host this entry applies to; `None` matches any host (`*` or empty).
    match_host: Option<String>,
    /// Port this entry applies to; `None` matches any port (`*` or empty).
    match_port: Option<u16>,
    /// Where to dial. For `--resolve` these are always IP literals and are
    /// tried in order; for `--connect-to` there is exactly one host or IP.
    targets: Vec<String>,
    /// Port to dial; `None` keeps the original port.
    target_port: Option<u16>,
    source: OverrideSource,
}

impl ConnectOverride {
    fn matches(&self, host: &str, port: u16) -> bool {
        if let Some(ref h) = self.match_host
            && !h.eq_ignore_ascii_case(host)
        {
            return false;
        }
        if let Some(p) = self.match_port
            && p != port
        {
            return false;
        }
        true
    }
}

/// The effective override for one connection attempt.
pub struct ResolvedOverride<'a> {
    /// Candidate hosts/IPs to dial, in order.
    pub targets: &'a [String],
    /// Port to dial.
    pub port: u16,
    pub source: OverrideSource,
}

impl ResolvedOverride<'_> {
    /// Human-readable summary, e.g. `--resolve api.example.com:443 -> 10.0.0.5:443`.
    pub fn describe(&self, host: &str, port: u16) -> String {
        format!(
            "{} {}:{} -> {}:{}",
            self.source,
            host,
            port,
            self.targets.join(","),
            self.port
        )
    }
}

/// Ordered set of connection overrides; first match wins.
#[derive(Debug, Clone, Default)]
pub struct ConnectOverrides {
    entries: Vec<ConnectOverride>,
}

impl ConnectOverrides {
    /// Build the table from the `--resolve` and `--connect-to` values, in that
    /// order. `--resolve` is listed first so a specific pin beats a broader
    /// `--connect-to` wildcard.
    pub fn new(resolve: &[ConnectOverride], connect_to: &[ConnectOverride]) -> Self {
        let mut entries = Vec::with_capacity(resolve.len() + connect_to.len());
        entries.extend_from_slice(resolve);
        entries.extend_from_slice(connect_to);
        Self { entries }
    }

    /// Find the first entry matching `host`/`port`, resolving the effective port.
    pub fn lookup(&self, host: &str, port: u16) -> Option<ResolvedOverride<'_>> {
        self.entries
            .iter()
            .find(|e| e.matches(host, port))
            .map(|e| ResolvedOverride {
                targets: &e.targets,
                port: e.target_port.unwrap_or(port),
                source: e.source,
            })
    }
}

/// Split on `:` while treating `[...]` as an opaque group, so bracketed IPv6
/// literals survive. Returns the raw fields, brackets stripped.
fn split_fields(s: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_bracket = false;

    for c in s.chars() {
        match c {
            '[' if !in_bracket => in_bracket = true,
            ']' if in_bracket => in_bracket = false,
            ':' if !in_bracket => {
                fields.push(std::mem::take(&mut current));
                continue;
            }
            _ => current.push(c),
        }
    }
    if in_bracket {
        return Err("unterminated '[' in IPv6 literal".to_string());
    }
    fields.push(current);
    Ok(fields)
}

/// Parse an optional host field: `*` or empty means "any".
fn parse_match_host(field: &str) -> Option<String> {
    match field.trim() {
        "" | "*" => None,
        h => Some(h.to_ascii_lowercase()),
    }
}

/// Parse an optional port field: `*` or empty means "any"/"unchanged".
fn parse_opt_port(field: &str, what: &str) -> Result<Option<u16>, String> {
    match field.trim() {
        "" | "*" => Ok(None),
        p => p
            .parse::<u16>()
            .map_err(|_| format!("{what} '{p}' is not a valid port number (1-65535)"))
            .and_then(|p| {
                if p == 0 {
                    Err(format!("{what} must not be 0"))
                } else {
                    Ok(Some(p))
                }
            }),
    }
}

/// Parse a `--resolve` value: `[+]HOST:PORT:ADDR[,ADDR...]`.
///
/// Doubles as a clap `value_parser`. A leading `+` (curl's "with TTL" marker) is
/// accepted and ignored; dcert has no resolver cache to expire.
pub fn parse_resolve(spec: &str) -> Result<ConnectOverride, String> {
    let spec = spec.strip_prefix('+').unwrap_or(spec);
    if let Some(rest) = spec.strip_prefix('-') {
        return Err(format!(
            "removing entries ('-{rest}') is not supported; omit the --resolve flag instead"
        ));
    }

    let fields = split_fields(spec)?;
    if fields.len() != 3 {
        return Err(format!(
            "'{spec}' must be HOST:PORT:ADDRESS (e.g. api.example.com:443:10.0.0.5); \
             wrap IPv6 addresses in brackets"
        ));
    }

    let match_host = parse_match_host(&fields[0]);
    let match_port = parse_opt_port(&fields[1], "--resolve port")?;

    let mut targets = Vec::new();
    for addr in fields[2].split(',') {
        let addr = addr.trim().trim_start_matches('[').trim_end_matches(']');
        if addr.is_empty() {
            continue;
        }
        // curl only accepts IP literals here; a hostname belongs in --connect-to.
        addr.parse::<IpAddr>().map_err(|_| {
            format!("--resolve address '{addr}' is not a valid IP address (use --connect-to for a hostname)")
        })?;
        targets.push(addr.to_string());
    }
    if targets.is_empty() {
        return Err(format!("'{spec}' has no target address"));
    }

    Ok(ConnectOverride {
        match_host,
        // A --resolve entry pins one host/port pair, so the dialled port is the
        // matched port unless the caller wildcarded it.
        target_port: match_port,
        match_port,
        targets,
        source: OverrideSource::Resolve,
    })
}

/// Parse a `--connect-to` value.
///
/// Accepts curl's `HOST1:PORT1:HOST2:PORT2` form, where any field may be empty
/// to mean "any"/"unchanged", and dcert's original bare `<IP>` form.
pub fn parse_connect_to(spec: &str) -> Result<ConnectOverride, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("--connect-to value must not be empty".to_string());
    }

    // Original dcert spelling: a bare IP address applying to every host/port.
    let bare = trimmed.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<IpAddr>().is_ok() {
        return Ok(ConnectOverride {
            match_host: None,
            match_port: None,
            targets: vec![bare.to_string()],
            target_port: None,
            source: OverrideSource::ConnectTo,
        });
    }

    let fields = split_fields(trimmed)?;
    if fields.len() != 4 {
        return Err(format!(
            "'{spec}' must be an IP address or HOST1:PORT1:HOST2:PORT2 \
             (e.g. api.example.com:443:origin.internal:8443); wrap IPv6 addresses in brackets"
        ));
    }

    let target_host = fields[2].trim();
    let targets = if target_host.is_empty() {
        return Err(format!("'{spec}' must name a host or IP to connect to (third field)"));
    } else {
        vec![target_host.to_string()]
    };

    Ok(ConnectOverride {
        match_host: parse_match_host(&fields[0]),
        match_port: parse_opt_port(&fields[1], "--connect-to source port")?,
        targets,
        target_port: parse_opt_port(&fields[3], "--connect-to target port")?,
        source: OverrideSource::ConnectTo,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overrides(resolve: &[&str], connect_to: &[&str]) -> ConnectOverrides {
        let r: Vec<_> = resolve.iter().map(|s| parse_resolve(s).unwrap()).collect();
        let c: Vec<_> = connect_to.iter().map(|s| parse_connect_to(s).unwrap()).collect();
        ConnectOverrides::new(&r, &c)
    }

    // -- --resolve parsing ------------------------------------------------

    #[test]
    fn resolve_parses_host_port_ip() {
        let o = parse_resolve("api.example.com:443:10.0.0.5").unwrap();
        assert_eq!(o.match_host.as_deref(), Some("api.example.com"));
        assert_eq!(o.match_port, Some(443));
        assert_eq!(o.targets, vec!["10.0.0.5"]);
        assert_eq!(o.target_port, Some(443));
        assert_eq!(o.source, OverrideSource::Resolve);
    }

    #[test]
    fn resolve_lowercases_match_host() {
        let o = parse_resolve("API.Example.COM:443:10.0.0.5").unwrap();
        assert_eq!(o.match_host.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn resolve_accepts_multiple_addresses() {
        let o = parse_resolve("h.example.com:443:10.0.0.5,10.0.0.6").unwrap();
        assert_eq!(o.targets, vec!["10.0.0.5", "10.0.0.6"]);
    }

    #[test]
    fn resolve_accepts_bracketed_ipv6() {
        let o = parse_resolve("h.example.com:443:[2001:db8::1]").unwrap();
        assert_eq!(o.targets, vec!["2001:db8::1"]);
    }

    #[test]
    fn resolve_accepts_wildcard_host() {
        let o = parse_resolve("*:443:10.0.0.5").unwrap();
        assert_eq!(o.match_host, None);
    }

    #[test]
    fn resolve_ignores_leading_plus() {
        assert_eq!(
            parse_resolve("+h.example.com:443:10.0.0.5").unwrap(),
            parse_resolve("h.example.com:443:10.0.0.5").unwrap()
        );
    }

    #[test]
    fn resolve_rejects_hostname_target() {
        let err = parse_resolve("api.example.com:443:origin.internal").unwrap_err();
        assert!(err.contains("not a valid IP address"), "got: {err}");
        assert!(err.contains("--connect-to"), "should point at --connect-to: {err}");
    }

    #[test]
    fn resolve_rejects_wrong_field_count() {
        assert!(
            parse_resolve("api.example.com:443")
                .unwrap_err()
                .contains("HOST:PORT:ADDRESS")
        );
        assert!(
            parse_resolve("api.example.com")
                .unwrap_err()
                .contains("HOST:PORT:ADDRESS")
        );
    }

    #[test]
    fn resolve_rejects_bad_port() {
        assert!(
            parse_resolve("h.example.com:notaport:10.0.0.5")
                .unwrap_err()
                .contains("port")
        );
        assert!(
            parse_resolve("h.example.com:0:10.0.0.5")
                .unwrap_err()
                .contains("must not be 0")
        );
    }

    #[test]
    fn resolve_rejects_removal_syntax() {
        assert!(
            parse_resolve("-h.example.com:443")
                .unwrap_err()
                .contains("not supported")
        );
    }

    #[test]
    fn resolve_rejects_unterminated_bracket() {
        assert!(
            parse_resolve("h.example.com:443:[2001:db8::1")
                .unwrap_err()
                .contains("unterminated")
        );
    }

    // -- --connect-to parsing ---------------------------------------------

    #[test]
    fn connect_to_accepts_bare_ip_for_backwards_compatibility() {
        let o = parse_connect_to("10.0.0.5").unwrap();
        assert_eq!(o.match_host, None);
        assert_eq!(o.match_port, None);
        assert_eq!(o.targets, vec!["10.0.0.5"]);
        assert_eq!(o.target_port, None, "bare IP keeps the original port");
    }

    #[test]
    fn connect_to_accepts_bare_ipv6() {
        assert_eq!(parse_connect_to("[2001:db8::1]").unwrap().targets, vec!["2001:db8::1"]);
        assert_eq!(parse_connect_to("2001:db8::1").unwrap().targets, vec!["2001:db8::1"]);
    }

    #[test]
    fn connect_to_accepts_four_field_form_with_hostname() {
        let o = parse_connect_to("api.example.com:443:origin.internal:8443").unwrap();
        assert_eq!(o.match_host.as_deref(), Some("api.example.com"));
        assert_eq!(o.match_port, Some(443));
        assert_eq!(o.targets, vec!["origin.internal"]);
        assert_eq!(o.target_port, Some(8443));
    }

    #[test]
    fn connect_to_treats_empty_fields_as_wildcards() {
        let o = parse_connect_to("::origin.internal:").unwrap();
        assert_eq!(o.match_host, None, "empty HOST1 matches any host");
        assert_eq!(o.match_port, None, "empty PORT1 matches any port");
        assert_eq!(o.target_port, None, "empty PORT2 keeps the original port");
        assert_eq!(o.targets, vec!["origin.internal"]);
    }

    #[test]
    fn connect_to_rejects_missing_target_host() {
        assert!(
            parse_connect_to("api.example.com:443::8443")
                .unwrap_err()
                .contains("must name a host")
        );
    }

    #[test]
    fn connect_to_rejects_wrong_field_count() {
        let err = parse_connect_to("api.example.com:443:origin.internal").unwrap_err();
        assert!(err.contains("HOST1:PORT1:HOST2:PORT2"), "got: {err}");
    }

    #[test]
    fn connect_to_rejects_empty() {
        assert!(parse_connect_to("   ").unwrap_err().contains("must not be empty"));
    }

    // -- lookup ------------------------------------------------------------

    #[test]
    fn lookup_returns_none_when_empty() {
        let o = ConnectOverrides::default();
        assert!(o.lookup("api.example.com", 443).is_none());
    }

    #[test]
    fn lookup_matches_host_and_port() {
        let o = overrides(&["api.example.com:443:10.0.0.5"], &[]);
        let m = o.lookup("api.example.com", 443).expect("should match");
        assert_eq!(m.targets, ["10.0.0.5"]);
        assert_eq!(m.port, 443);
    }

    #[test]
    fn lookup_is_case_insensitive_on_host() {
        let o = overrides(&["api.example.com:443:10.0.0.5"], &[]);
        assert!(o.lookup("API.EXAMPLE.COM", 443).is_some());
    }

    #[test]
    fn lookup_skips_entry_with_different_port() {
        let o = overrides(&["api.example.com:443:10.0.0.5"], &[]);
        assert!(o.lookup("api.example.com", 8443).is_none());
    }

    #[test]
    fn lookup_skips_entry_with_different_host() {
        let o = overrides(&["api.example.com:443:10.0.0.5"], &[]);
        assert!(o.lookup("other.example.com", 443).is_none());
    }

    #[test]
    fn lookup_first_match_wins() {
        let o = overrides(&["api.example.com:443:10.0.0.5", "api.example.com:443:10.0.0.9"], &[]);
        assert_eq!(o.lookup("api.example.com", 443).unwrap().targets, ["10.0.0.5"]);
    }

    #[test]
    fn lookup_prefers_resolve_over_connect_to_wildcard() {
        let o = overrides(&["api.example.com:443:10.0.0.5"], &["10.9.9.9"]);
        assert_eq!(o.lookup("api.example.com", 443).unwrap().targets, ["10.0.0.5"]);
        assert_eq!(
            o.lookup("other.example.com", 443).unwrap().targets,
            ["10.9.9.9"],
            "the wildcard still catches everything else"
        );
    }

    #[test]
    fn lookup_keeps_original_port_for_bare_ip() {
        let o = overrides(&[], &["10.0.0.5"]);
        assert_eq!(o.lookup("api.example.com", 8443).unwrap().port, 8443);
    }

    #[test]
    fn lookup_applies_target_port() {
        let o = overrides(&[], &["api.example.com:443:origin.internal:8443"]);
        assert_eq!(o.lookup("api.example.com", 443).unwrap().port, 8443);
    }

    #[test]
    fn describe_reads_naturally() {
        let o = overrides(&["api.example.com:443:10.0.0.5"], &[]);
        let m = o.lookup("api.example.com", 443).unwrap();
        assert_eq!(
            m.describe("api.example.com", 443),
            "--resolve api.example.com:443 -> 10.0.0.5:443"
        );
    }
}
