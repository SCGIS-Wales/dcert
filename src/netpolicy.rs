//! Destination policy: which hosts and addresses dcert may connect to.
//!
//! Two consumers share it. The MCP server checks every destination a tool
//! call names (target, `connect_to`, `resolve`, `proxy`) before it starts a
//! child, using `DCERT_MCP_ALLOWED_TARGETS` and
//! `DCERT_MCP_DENY_PRIVATE_TARGETS`. It hands the effective policy to the
//! child as `DCERT_ALLOWED_TARGETS` and `DCERT_DENY_PRIVATE_TARGETS`, and the
//! CLI enforces it again on the address each socket actually connects to and
//! on AIA issuer URLs, so a name that resolves differently the second time
//! (DNS rebinding) is still refused for direct connections.
//!
//! Rules:
//! - With an allow list, a destination must match it: a hostname (exact), a
//!   suffix pattern (`.corp.example` matches `api.corp.example`), an IP
//!   address or a CIDR range. A match overrides the private range denial.
//! - Without an allow list and with private denial on, loopback, RFC 1918,
//!   link local (including the `169.254.169.254` metadata address), carrier
//!   grade NAT, unique local IPv6 (including `fd00:ec2::254`) and the other
//!   ranges of [`is_internal_ip`] are refused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::OnceLock;

/// Environment variables the CLI reads (set by the MCP server for its child).
pub const ALLOWED_TARGETS_ENV: &str = "DCERT_ALLOWED_TARGETS";
/// See [`ALLOWED_TARGETS_ENV`].
pub const DENY_PRIVATE_TARGETS_ENV: &str = "DCERT_DENY_PRIVATE_TARGETS";

/// Whether `ip` is in a range a fetch on behalf of a remote party must never
/// reach: loopback, unspecified, RFC 1918, link local, carrier grade NAT
/// (100.64.0.0/10), the IETF protocol block 192.0.0.0/24, documentation
/// networks, multicast, the reserved 240.0.0.0/4, broadcast, unique local
/// IPv6 (fc00::/7) and link local IPv6 (fe80::/10). IPv4 mapped IPv6
/// addresses get the IPv4 rules.
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => is_internal_v6(v6),
    }
}

fn is_internal_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_documentation()
        || v4.is_multicast()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || a >= 240
}

fn is_internal_v6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_internal_v4(v4);
    }
    let first = v6.segments()[0];
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || (first & 0xffc0) == 0xfe80
        || (first & 0xfe00) == 0xfc00
}

/// Whether a host taken from a URL is safe to contact when it is an IP
/// literal. Hostnames pass here; their resolved addresses are checked
/// separately.
pub fn is_safe_host_literal(host: &str) -> bool {
    host_ip(host).is_none_or(|ip| !is_internal_ip(ip))
}

/// The IP address a host string spells, accepting `[v6]`.
fn host_ip(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

/// One allow list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    Host(String),
    Suffix(String),
    Ip(IpAddr),
    Cidr(IpAddr, u8),
}

impl Rule {
    fn parse(raw: &str) -> Result<Self, String> {
        let entry = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if entry.is_empty() {
            return Err("empty entry".to_string());
        }
        if let Some((net, len)) = entry.split_once('/') {
            let ip: IpAddr = net.parse().map_err(|_| format!("'{raw}' is not a valid CIDR range"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let len: u8 = len
                .parse()
                .ok()
                .filter(|l| *l <= max)
                .ok_or_else(|| format!("'{raw}' has an invalid prefix length"))?;
            return Ok(Self::Cidr(ip, len));
        }
        if let Some(ip) = host_ip(&entry) {
            return Ok(Self::Ip(ip));
        }
        if let Some(suffix) = entry.strip_prefix("*.") {
            return Ok(Self::Suffix(format!(".{suffix}")));
        }
        if entry.starts_with('.') {
            return Ok(Self::Suffix(entry));
        }
        if entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        {
            return Ok(Self::Host(entry));
        }
        Err(format!("'{raw}' is not a hostname, suffix, IP address or CIDR range"))
    }

    fn matches_name(&self, host: &str) -> bool {
        match self {
            Self::Host(h) => h == host,
            Self::Suffix(s) => host.ends_with(s.as_str()) || host == &s[1..],
            Self::Ip(_) | Self::Cidr(..) => false,
        }
    }

    fn matches_ip(&self, ip: IpAddr) -> bool {
        match *self {
            Self::Ip(rule) => canonical(rule) == canonical(ip),
            Self::Cidr(net, len) => in_cidr(canonical(ip), canonical(net), len),
            Self::Host(_) | Self::Suffix(_) => false,
        }
    }
}

/// IPv4 mapped IPv6 addresses compare as IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn in_cidr(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// Lower case a host and drop brackets and a trailing dot.
fn normalise_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Which destinations may be contacted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationPolicy {
    allow: Vec<Rule>,
    deny_private: bool,
    /// Variable names quoted in refusals, so the message points at the
    /// setting the reader controls.
    allow_var: &'static str,
    deny_var: &'static str,
}

/// Parse a boolean environment value (`1`, `true`, `yes`, `on`, `0`, `false`,
/// `no`, `off`, case insensitive).
fn parse_bool(raw: &str, name: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("{name} must be 1 or 0, got '{other}'")),
    }
}

impl DestinationPolicy {
    /// Build a policy from the raw values of the two variables named
    /// `allow_var` and `deny_var`. `default_deny_private` applies when the
    /// deny variable is unset or empty.
    pub fn parse(
        allowed: Option<&str>,
        deny_private: Option<&str>,
        default_deny_private: bool,
        allow_var: &'static str,
        deny_var: &'static str,
    ) -> Result<Self, String> {
        let allow = allowed
            .unwrap_or("")
            .split(',')
            .filter(|e| !e.trim().is_empty())
            .map(|e| Rule::parse(e).map_err(|err| format!("{allow_var}: {err}")))
            .collect::<Result<Vec<_>, _>>()?;
        let deny_private = match deny_private.map(str::trim).filter(|v| !v.is_empty()) {
            Some(raw) => parse_bool(raw, deny_var)?,
            None => default_deny_private,
        };
        Ok(Self {
            allow,
            deny_private,
            allow_var,
            deny_var,
        })
    }

    /// The policy the CLI enforces, from [`ALLOWED_TARGETS_ENV`] and
    /// [`DENY_PRIVATE_TARGETS_ENV`]; open when neither is set.
    pub fn from_cli_env() -> Result<Self, String> {
        Self::parse(
            std::env::var(ALLOWED_TARGETS_ENV).ok().as_deref(),
            std::env::var(DENY_PRIVATE_TARGETS_ENV).ok().as_deref(),
            false,
            ALLOWED_TARGETS_ENV,
            DENY_PRIVATE_TARGETS_ENV,
        )
    }

    /// Whether the policy restricts anything at all.
    pub fn is_open(&self) -> bool {
        self.allow.is_empty() && !self.deny_private
    }

    /// Whether private ranges are refused.
    pub fn denies_private(&self) -> bool {
        self.deny_private
    }

    /// The allow list in its environment variable form, for handing the
    /// policy to a child process.
    pub fn allow_list_env(&self) -> String {
        self.allow
            .iter()
            .map(|r| match r {
                Rule::Host(h) | Rule::Suffix(h) => h.clone(),
                Rule::Ip(ip) => ip.to_string(),
                Rule::Cidr(ip, len) => format!("{ip}/{len}"),
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn name_allowed(&self, host: &str) -> bool {
        self.allow.iter().any(|r| r.matches_name(host))
    }

    fn ip_allowed(&self, ip: IpAddr) -> bool {
        self.allow.iter().any(|r| r.matches_ip(ip))
    }

    /// Check a destination the caller named, resolving hostnames with
    /// `resolve`. A name that does not resolve passes: the connection will
    /// fail on its own, and refusing would turn the check into a DNS oracle.
    pub fn check_with(&self, host: &str, port: u16, resolve: impl Fn(&str, u16) -> Vec<IpAddr>) -> Result<(), String> {
        if self.is_open() {
            return Ok(());
        }
        let host = normalise_host(host);
        if self.name_allowed(&host) {
            return Ok(());
        }
        let ips = match host_ip(&host) {
            Some(ip) => vec![ip],
            None => resolve(&host, port),
        };
        if !self.allow.is_empty() {
            return if !ips.is_empty() && ips.iter().all(|ip| self.ip_allowed(*ip)) {
                Ok(())
            } else {
                Err(format!("destination '{host}' is not in {}", self.allow_var))
            };
        }
        match ips.iter().find(|ip| is_internal_ip(**ip)) {
            Some(ip) => Err(format!(
                "destination '{host}' ({ip}) is a private, loopback or link local address, refused by {}; \
                 list it in {} to allow it",
                self.deny_var, self.allow_var
            )),
            None => Ok(()),
        }
    }

    /// [`Self::check_with`] resolving through the system resolver.
    pub fn check(&self, host: &str, port: u16) -> Result<(), String> {
        self.check_with(host, port, system_resolve)
    }

    /// Check the address a socket is about to connect to, for `host`.
    pub fn check_addr(&self, host: &str, addr: &SocketAddr) -> Result<(), String> {
        if self.is_open() {
            return Ok(());
        }
        let host = normalise_host(host);
        if self.name_allowed(&host) || self.ip_allowed(addr.ip()) {
            return Ok(());
        }
        if !self.allow.is_empty() {
            return Err(format!(
                "destination '{host}' ({}) is not in {}",
                addr.ip(),
                self.allow_var
            ));
        }
        if self.deny_private && is_internal_ip(addr.ip()) {
            return Err(format!(
                "destination '{host}' ({}) is a private, loopback or link local address, refused by {}",
                addr.ip(),
                self.deny_var
            ));
        }
        Ok(())
    }
}

fn system_resolve(host: &str, port: u16) -> Vec<IpAddr> {
    (host, port)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// The CLI's policy, read from the environment once per process. A
/// malformed value is reported on first use and treated as deny all, so a
/// typo cannot silently open the policy.
pub fn cli_policy() -> Result<&'static DestinationPolicy, String> {
    static POLICY: OnceLock<Result<DestinationPolicy, String>> = OnceLock::new();
    POLICY
        .get_or_init(DestinationPolicy::from_cli_env)
        .as_ref()
        .map_err(Clone::clone)
}

/// Enforce the CLI policy on a socket address about to be dialled.
pub fn enforce_addr(host: &str, addr: &SocketAddr) -> anyhow::Result<()> {
    cli_policy()
        .and_then(|p| p.check_addr(host, addr))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Enforce the CLI policy on a URL host before an HTTP client fetches it.
pub fn enforce_url(url: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid URL '{url}': {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL '{url}' has no host"))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    cli_policy()
        .and_then(|p| p.check(host, port))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "DCERT_MCP_ALLOWED_TARGETS";
    const D: &str = "DCERT_MCP_DENY_PRIVATE_TARGETS";

    fn policy(allowed: &str, deny: &str) -> DestinationPolicy {
        DestinationPolicy::parse(Some(allowed), Some(deny), false, A, D).expect("policy")
    }

    fn no_dns(_: &str, _: u16) -> Vec<IpAddr> {
        Vec::new()
    }

    fn resolves_to(ip: &'static str) -> impl Fn(&str, u16) -> Vec<IpAddr> {
        move |_, _| vec![ip.parse().expect("ip")]
    }

    #[test]
    fn every_internal_range_is_refused_when_private_is_denied() {
        let p = policy("", "1");
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "169.254.169.254",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            let err = p.check_with(ip, 443, no_dns).expect_err(ip);
            assert!(err.contains(D) && err.contains(A), "{ip}: {err}");
        }
    }

    #[test]
    fn public_addresses_pass_when_private_is_denied() {
        let p = policy("", "1");
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "100.128.0.1"] {
            assert!(p.check_with(ip, 443, no_dns).is_ok(), "{ip}");
        }
    }

    #[test]
    fn a_name_resolving_to_a_private_address_is_refused() {
        let p = policy("", "1");
        let err = p
            .check_with("metadata.example", 80, resolves_to("169.254.169.254"))
            .expect_err("rebinding name");
        assert!(err.contains("169.254.169.254"), "{err}");
        assert!(
            p.check_with("public.example", 443, resolves_to("93.184.216.34"))
                .is_ok()
        );
        assert!(p.check_with("unresolvable.example", 443, no_dns).is_ok());
    }

    #[test]
    fn open_policy_allows_everything() {
        let p = policy("", "0");
        assert!(p.is_open());
        assert!(p.check_with("127.0.0.1", 443, no_dns).is_ok());
    }

    #[test]
    fn allow_list_admits_hosts_suffixes_ips_and_cidrs_and_overrides_private() {
        let p = policy(
            "api.example.com, .corp.example, 10.0.0.5, 192.168.0.0/16, fd00::/8",
            "1",
        );
        assert!(p.check_with("API.example.com.", 443, no_dns).is_ok());
        assert!(p.check_with("svc.corp.example", 443, resolves_to("10.9.9.9")).is_ok());
        assert!(p.check_with("corp.example", 443, no_dns).is_ok());
        assert!(p.check_with("10.0.0.5", 443, no_dns).is_ok());
        assert!(p.check_with("192.168.7.7", 443, no_dns).is_ok());
        assert!(p.check_with("[fd00::1]", 443, no_dns).is_ok());
        assert!(p.check_with("internal", 443, resolves_to("192.168.1.1")).is_ok());
    }

    #[test]
    fn allow_list_refuses_everything_else() {
        let p = policy("api.example.com,10.0.0.0/8", "0");
        for (host, dns) in [("other.example.com", "93.184.216.34"), ("8.8.8.8", "8.8.8.8")] {
            let err = p.check_with(host, 443, resolves_to(dns)).expect_err(host);
            assert!(err.contains(A), "{err}");
        }
        assert!(p.check_with("unresolvable.example", 443, no_dns).is_err());
        assert!(p.check_with("evilcorp.example", 443, no_dns).is_err());
    }

    #[test]
    fn suffix_does_not_match_a_longer_label() {
        let p = policy(".corp.example", "0");
        assert!(p.check_with("badcorp.example", 443, no_dns).is_err());
    }

    #[test]
    fn socket_level_check_catches_rebinding() {
        let p = policy("", "1");
        let addr: SocketAddr = "127.0.0.1:443".parse().expect("addr");
        assert!(p.check_addr("public.example", &addr).is_err());
        let addr: SocketAddr = "93.184.216.34:443".parse().expect("addr");
        assert!(p.check_addr("public.example", &addr).is_ok());
        let p = policy("10.0.0.0/8", "1");
        let addr: SocketAddr = "10.1.1.1:443".parse().expect("addr");
        assert!(p.check_addr("svc", &addr).is_ok());
    }

    #[test]
    fn malformed_entries_and_flags_are_rejected() {
        assert!(DestinationPolicy::parse(Some("10.0.0.0/33"), None, false, A, D).is_err());
        assert!(DestinationPolicy::parse(Some("host with space"), None, false, A, D).is_err());
        assert!(DestinationPolicy::parse(None, Some("maybe"), false, A, D).is_err());
        assert!(
            DestinationPolicy::parse(None, None, true, A, D)
                .expect("default")
                .denies_private()
        );
    }

    #[test]
    fn allow_list_round_trips_through_its_env_form() {
        let p = policy("api.example.com,.corp.example,10.0.0.5,10.0.0.0/8", "1");
        let again = policy(&p.allow_list_env(), "1");
        assert_eq!(p, again);
    }

    #[test]
    fn literal_check_matches_the_old_ocsp_guard() {
        assert!(!is_safe_host_literal("[::1]"));
        assert!(!is_safe_host_literal("192.0.0.8"));
        assert!(!is_safe_host_literal("240.0.0.1"));
        assert!(!is_safe_host_literal("ff02::1"));
        assert!(is_safe_host_literal("ocsp.digicert.com"));
        assert!(is_safe_host_literal("8.8.8.8"));
    }
}
