//! The TLS and connection settings every probe shares, and the one builder
//! that turns them into handshake options.
//!
//! [`TlsOptions`] owns every TLS knob and [`ConnectionOptions`] owns how the
//! probe reaches its peer. Commands flatten both into their arguments, so a
//! flag exists once, behaves the same everywhere and cannot drift between
//! `check`, `verify-key` and the MCP tools. [`ProbeOptions`] combines them
//! with the client identity, resolves the TLS profile, the proxy and the
//! connection overrides once per run, and lends out [`TlsProbeOptions`].

use anyhow::Result;
use clap::Args;

use crate::ciphers::{Cipher, CipherSet, parse_cipher_arg};
use crate::cli::{CipherNotation, StarttlsProtocol, TlsVersionArg};
use crate::connect::{ConnectOverride, ConnectOverrides, parse_connect_to, parse_resolve};
use crate::keyex::{EffectiveTlsSettings, TlsProfile, effective_tls_settings};
use crate::proxy::ProxyConfig;
use crate::tls::{ClientIdentity, TlsProbeOptions};

/// Validate an OpenSSL group list before it reaches libssl.
fn parse_groups(value: &str) -> Result<String, String> {
    crate::keyex::validate_groups_list(value).map(|()| value.trim().to_string())
}

/// Every TLS setting a probe can take.
#[derive(Args, Debug, Clone, Default)]
#[command(next_help_heading = "TLS options")]
pub struct TlsOptions {
    /// Minimum TLS version to accept [possible values: 1.0, 1.1, 1.2, 1.3]
    ///
    /// 1.0 and 1.1 are deprecated (RFC 8996) and need --allow-legacy-tls.
    #[arg(long, value_enum, value_name = "VERSION")]
    pub min_tls: Option<TlsVersionArg>,

    /// Maximum TLS version to accept [possible values: 1.0, 1.1, 1.2, 1.3]
    #[arg(long, value_enum, value_name = "VERSION")]
    pub max_tls: Option<TlsVersionArg>,

    /// Offer TLS 1.0 and 1.1, deprecated by RFC 8996, to probe legacy
    /// servers. Sets OpenSSL security level 0 for the handshake (legacy
    /// versions sign with SHA-1 and MD5) and prints a warning. Without
    /// --min-tls the floor becomes TLS 1.0.
    #[arg(long)]
    pub allow_legacy_tls: bool,

    /// Offer only this cipher suite, in any notation: IANA name
    /// (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256), OpenSSL name
    /// (ECDHE-RSA-AES128-GCM-SHA256) or code point (0xC02F, C02F, 0xC0,0x2F).
    ///
    /// Repeatable. TLS 1.2 and TLS 1.3 suites may be mixed; dcert configures
    /// each family. Naming only TLS 1.3 suites limits the handshake to TLS
    /// 1.3, and naming only TLS 1.2 suites limits it to TLS 1.2.
    #[arg(long, value_name = "SUITE", value_parser = parse_cipher_arg,
          conflicts_with_all = ["cipher_list", "cipher_suites"])]
    pub cipher: Vec<&'static Cipher>,

    /// Set allowed TLS cipher suites using an OpenSSL cipher string (e.g. "ECDHE+AESGCM:CHACHA20")
    ///
    /// Controls TLS 1.2 and below ciphers and is passed to OpenSSL as is.
    /// Use --cipher to name suites in any notation.
    /// See: https://docs.openssl.org/master/man1/openssl-ciphers/
    #[arg(long, value_name = "CIPHER_STRING")]
    pub cipher_list: Option<String>,

    /// Set allowed TLS 1.3 cipher suites (e.g. "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
    ///
    /// Controls TLS 1.3 ciphers only and is passed to OpenSSL as is.
    #[arg(long, value_name = "CIPHERSUITES")]
    pub cipher_suites: Option<String>,

    /// Key exchange groups to offer, as an OpenSSL group list
    /// (e.g. "X25519MLKEM768:X25519:secp384r1"). Post quantum hybrids
    /// (RFC 10024) need OpenSSL 3.5 or later; the default keeps the linked
    /// library's own list, which on 3.5+ already offers X25519MLKEM768.
    #[arg(long, value_name = "GROUPS", value_parser = parse_groups)]
    pub groups: Option<String>,

    /// Apply a named TLS client profile (Mozilla configurator v6): `modern`
    /// is TLS 1.3 only, `intermediate` adds forward secret AEAD TLS 1.2
    /// suites. Both put X25519MLKEM768 first when OpenSSL supports it.
    /// Explicit --min-tls, --cipher-list, --cipher-suites and --groups win.
    #[arg(long, value_enum, value_name = "PROFILE")]
    pub tls_profile: Option<TlsProfile>,

    /// Run a second handshake offering only the RFC 10024 hybrid post quantum
    /// groups and report whether the server supports post quantum key
    /// agreement (requires OpenSSL 3.5 or later; reported as not testable otherwise).
    #[arg(long)]
    pub pq_probe: bool,

    /// Override SNI hostname for TLS handshake
    #[arg(long)]
    pub sni: Option<String>,

    /// Perform STARTTLS negotiation before the TLS handshake (for mail/FTP
    /// servers). The target is treated as host[:port], not an HTTPS URL.
    ///
    /// Cannot be combined with the HTTP request options (--method, --header,
    /// --data, --data-file, --http-protocol): STARTTLS inspects the certificate
    /// over a plain protocol upgrade and never sends an HTTP request.
    #[arg(long, value_enum, value_name = "PROTOCOL")]
    pub starttls: Option<StarttlsProtocol>,

    /// Report the negotiated (agreed) TLS cipher suite in the given notation,
    /// in pretty, JSON and YAML output [default: all]. `all` gives the OpenSSL
    /// and IANA names, code point, protocol, forward secrecy and AEAD.
    /// `--ciphers` is accepted as an alias.
    #[arg(long = "cipher-notation", alias = "ciphers", value_enum, value_name = "NOTATION")]
    pub cipher_notation: Option<CipherNotation>,
}

impl TlsOptions {
    /// The profile combined with the explicit flags; explicit flags win.
    /// `--cipher` sets both cipher lists and, when it names one family only,
    /// bounds the version to that family.
    pub fn effective(&self) -> EffectiveTlsSettings {
        let mut settings = effective_tls_settings(
            self.tls_profile,
            self.min_tls,
            self.cipher_list.as_deref(),
            self.cipher_suites.as_deref(),
            self.groups.as_deref(),
        );
        settings.max_tls = self.max_tls;
        if self.allow_legacy_tls {
            settings.min_tls = Some(self.min_tls.unwrap_or(TlsVersionArg::Tls1_0));
        }
        if !self.cipher.is_empty() {
            let set = CipherSet::from_ciphers(&self.cipher);
            settings.cipher_list = set.cipher_list();
            settings.cipher_suites = set.ciphersuites();
            if set.tls12.is_empty() {
                settings.min_tls = Some(TlsVersionArg::Tls1_3);
            }
            if set.tls13.is_empty() {
                settings.max_tls = Some(TlsVersionArg::Tls1_2);
            }
        }
        if self.allow_legacy_tls {
            // Legacy handshakes sign with SHA-1 and MD5, which security
            // level 1 and above refuse.
            settings.cipher_list = Some(format!(
                "{}:@SECLEVEL=0",
                settings.cipher_list.as_deref().unwrap_or("DEFAULT")
            ));
        }
        settings
    }

    /// The notation the negotiated cipher is reported in.
    pub fn notation(&self) -> CipherNotation {
        self.cipher_notation.unwrap_or_default()
    }

    /// Reject a version range that no handshake can satisfy.
    pub fn validate(&self) -> Result<()> {
        if let (Some(min), Some(max)) = (self.min_tls, self.max_tls)
            && min > max
        {
            anyhow::bail!("--min-tls ({min}) must not be greater than --max-tls ({max})");
        }
        let legacy = [self.min_tls, self.max_tls]
            .into_iter()
            .flatten()
            .any(TlsVersionArg::is_legacy);
        if legacy && !self.allow_legacy_tls {
            anyhow::bail!(
                "TLS 1.0 and 1.1 are deprecated (RFC 8996) and not offered by default; add --allow-legacy-tls to probe them"
            );
        }
        let set = CipherSet::from_ciphers(&self.cipher);
        if let Some(max) = self.max_tls.filter(|m| *m < TlsVersionArg::Tls1_3)
            && !self.cipher.is_empty()
            && set.tls12.is_empty()
        {
            anyhow::bail!(
                "--cipher names only TLS 1.3 suites, which --max-tls {} rules out",
                max.number()
            );
        }
        if !self.cipher.is_empty() && set.tls13.is_empty() && self.min_tls == Some(TlsVersionArg::Tls1_3) {
            anyhow::bail!("--cipher names only TLS 1.2 suites, which --min-tls 1.3 rules out");
        }
        Ok(())
    }
}

/// How a probe reaches its peer and how long it may take.
#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Connection options")]
pub struct ConnectionOptions {
    /// Disable TLS certificate verification (insecure)
    #[arg(long)]
    pub no_verify: bool,

    /// TCP connect timeout in seconds — how long to wait to *establish* the
    /// connection. Does not bound the response wait (see --read-timeout).
    #[arg(long, value_name = "SECONDS", default_value_t = crate::limits::DEFAULT_TIMEOUT_SECS,
          value_parser = clap::value_parser!(u64).range(crate::limits::TIMEOUT_RANGE))]
    pub timeout: u64,

    /// Read timeout in seconds — how long each read may wait for the server.
    /// Everything after the TCP connect (proxy CONNECT, STARTTLS, the TLS
    /// handshake and the HTTP exchange) also shares one wall clock budget of
    /// --timeout plus --read-timeout, so a server that trickles bytes cannot
    /// hold a probe open.
    #[arg(long, value_name = "SECONDS", default_value_t = crate::limits::DEFAULT_READ_TIMEOUT_SECS,
          value_parser = clap::value_parser!(u64).range(crate::limits::READ_TIMEOUT_RANGE))]
    pub read_timeout: u64,

    /// Pin HOST:PORT to a specific IP address instead of using DNS, like curl's
    /// --resolve. The hostname is still used for SNI, the Host header and
    /// certificate validation. Repeatable; the host may be `*` and several
    /// comma-separated addresses may be given (tried in order). Use
    /// --connect-to to redirect to a hostname rather than an IP. Example:
    /// `dcert https://api.example.com --resolve api.example.com:443:10.0.0.5`
    #[arg(long, value_name = "HOST:PORT:ADDRESS", value_parser = parse_resolve)]
    pub resolve: Vec<ConnectOverride>,

    /// Redirect the connection to another host or IP while keeping the target
    /// hostname for SNI, the Host header and certificate validation. Accepts a
    /// bare IP address, or curl's HOST1:PORT1:HOST2:PORT2 form where empty
    /// fields mean "any"/"unchanged". Repeatable. Example:
    /// `dcert https://api.example.com --connect-to api.example.com:443:origin.internal:8443`
    #[arg(long, value_name = "IP|HOST1:PORT1:HOST2:PORT2", value_parser = parse_connect_to)]
    pub connect_to: Vec<ConnectOverride>,

    /// Forward proxy URL for HTTPS/HTTP requests, like curl's -x. Overrides the
    /// HTTPS_PROXY/HTTP_PROXY environment variables. Credentials may be embedded
    /// (http://user:pass@proxy:3128). Pass an empty value to force a direct
    /// connection. Note that --resolve/--connect-to always bypass the proxy.
    #[arg(long, value_name = "URL", env = "DCERT_PROXY", hide_env_values = true)]
    pub proxy: Option<String>,

    /// Comma-separated list of hosts that must bypass the proxy, like curl's
    /// --noproxy. Overrides NO_PROXY; `*` bypasses the proxy entirely and an
    /// empty value clears an inherited NO_PROXY.
    #[arg(long = "noproxy", value_name = "LIST", env = "DCERT_NOPROXY", hide_env_values = true)]
    pub noproxy: Option<String>,

    /// Custom CA certificate bundle PEM file for server verification (overrides system CAs)
    #[arg(long, value_name = "PATH")]
    pub ca_cert: Option<String>,
}

impl Default for ConnectionOptions {
    /// The same values clap gives a command line without connection flags.
    fn default() -> Self {
        Self {
            no_verify: false,
            timeout: crate::limits::DEFAULT_TIMEOUT_SECS,
            read_timeout: crate::limits::DEFAULT_READ_TIMEOUT_SECS,
            resolve: Vec::new(),
            connect_to: Vec::new(),
            proxy: None,
            noproxy: None,
            ca_cert: None,
        }
    }
}

/// The client certificate a probe presents for mutual TLS.
#[derive(Args, Debug, Clone, Default)]
#[command(next_help_heading = "Client certificate (mTLS)")]
pub struct IdentityOptions {
    /// Client certificate PEM file for mutual TLS authentication
    #[arg(long, value_name = "PATH", requires = "client_key")]
    pub client_cert: Option<String>,

    /// Client private key PEM file for mutual TLS (unencrypted RSA/EC key)
    #[arg(long, value_name = "PATH", requires = "client_cert", conflicts_with = "pkcs12")]
    pub client_key: Option<String>,

    /// PKCS12/PFX file containing client certificate and private key for mTLS
    #[arg(long, value_name = "PATH", conflicts_with_all = ["client_cert", "client_key"])]
    pub pkcs12: Option<String>,

    /// Password for the PKCS12/PFX file (or set DCERT_CERT_PASSWORD env var)
    #[arg(long, value_name = "PASS", env = "DCERT_CERT_PASSWORD", hide_env_values = true)]
    pub cert_password: Option<crate::secret::Secret>,
}

impl IdentityOptions {
    /// The identity, borrowed from these options.
    pub fn identity(&self) -> ClientIdentity<'_> {
        ClientIdentity {
            client_cert_path: self.client_cert.as_deref(),
            client_key_path: self.client_key.as_deref(),
            pkcs12_path: self.pkcs12.as_deref(),
            cert_password: self.cert_password.as_deref(),
        }
    }
}

/// Everything a handshake needs, resolved once per run from the TLS and
/// connection options and the client identity.
#[derive(Debug)]
pub struct ProbeOptions<'a> {
    pub tls: &'a TlsOptions,
    pub connection: &'a ConnectionOptions,
    pub identity: ClientIdentity<'a>,
    /// The TLS profile combined with the explicit flags.
    pub settings: EffectiveTlsSettings,
    /// `--proxy` and `--noproxy` layered over the proxy environment variables.
    pub proxy: ProxyConfig,
    /// The `--resolve` and `--connect-to` table.
    pub connect_overrides: ConnectOverrides,
    pub debug: bool,
}

impl<'a> ProbeOptions<'a> {
    /// Validate and resolve the options. Fails on an impossible TLS version
    /// range or an unusable proxy URL.
    pub fn new(
        tls: &'a TlsOptions,
        connection: &'a ConnectionOptions,
        identity: ClientIdentity<'a>,
        debug: bool,
    ) -> Result<Self> {
        tls.validate()?;
        if tls.allow_legacy_tls {
            eprintln!(
                "Warning: --allow-legacy-tls offers deprecated TLS 1.0 and 1.1 at OpenSSL security level 0; use it to probe legacy servers only"
            );
        }
        Ok(Self {
            tls,
            connection,
            identity,
            settings: tls.effective(),
            proxy: ProxyConfig::resolve(connection.proxy.as_deref(), connection.noproxy.as_deref())?,
            connect_overrides: ConnectOverrides::new(&connection.resolve, &connection.connect_to),
            debug,
        })
    }

    /// The handshake settings, borrowed from these options.
    pub fn tls_probe(&self) -> TlsProbeOptions<'_> {
        TlsProbeOptions {
            no_verify: self.connection.no_verify,
            timeout_secs: self.connection.timeout,
            read_timeout_secs: self.connection.read_timeout,
            sni_override: self.tls.sni.as_deref(),
            connect_overrides: &self.connect_overrides,
            min_tls: self.settings.min_tls,
            max_tls: self.settings.max_tls,
            cipher_list: self.settings.cipher_list.as_deref(),
            cipher_suites: self.settings.cipher_suites.as_deref(),
            groups: self.settings.groups.as_deref(),
            ca_cert_path: self.connection.ca_cert.as_deref(),
            debug: self.debug,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        tls: TlsOptions,
        #[command(flatten)]
        connection: ConnectionOptions,
    }

    fn parse(args: &[&str]) -> Harness {
        Harness::try_parse_from(std::iter::once("dcert").chain(args.iter().copied())).expect("parses")
    }

    #[test]
    fn defaults_match_the_command_line_defaults() {
        let parsed = parse(&[]);
        let default = ConnectionOptions::default();
        assert_eq!(parsed.connection.timeout, default.timeout);
        assert_eq!(parsed.connection.read_timeout, default.read_timeout);
        assert!(!parsed.connection.no_verify && !default.no_verify);
        assert!(parsed.tls.cipher_notation.is_none());
        assert_eq!(parsed.tls.notation(), CipherNotation::All);
        assert!(parsed.tls.cipher.is_empty());
    }

    #[test]
    fn ciphers_stays_an_alias_of_cipher_notation() {
        let old = parse(&["--ciphers", "iana"]);
        let new = parse(&["--cipher-notation", "iana"]);
        assert!(matches!(old.tls.cipher_notation, Some(CipherNotation::Iana)));
        assert!(matches!(new.tls.cipher_notation, Some(CipherNotation::Iana)));
    }

    fn probe_settings(args: &[&str]) -> EffectiveTlsSettings {
        parse(args).tls.effective()
    }

    #[test]
    fn cipher_accepts_every_notation_and_fills_both_lists() {
        let settings = probe_settings(&["--cipher", "0xC0,0x2F", "--cipher", "TLS_AES_128_GCM_SHA256"]);
        assert_eq!(settings.cipher_list.as_deref(), Some("ECDHE-RSA-AES128-GCM-SHA256"));
        assert_eq!(settings.cipher_suites.as_deref(), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!((settings.min_tls, settings.max_tls), (None, None));
        let same = probe_settings(&["--cipher", "ecdhe-rsa-aes128-gcm-sha256", "--cipher", "1301"]);
        assert_eq!(same, settings);
    }

    #[test]
    fn one_family_bounds_the_version() {
        let tls13 = probe_settings(&["--cipher", "TLS_CHACHA20_POLY1305_SHA256"]);
        assert_eq!(tls13.min_tls, Some(TlsVersionArg::Tls1_3));
        assert_eq!(tls13.cipher_list, None);
        let tls12 = probe_settings(&["--cipher", "C02F"]);
        assert_eq!(tls12.max_tls, Some(TlsVersionArg::Tls1_2));
        assert_eq!(tls12.cipher_suites, None);
        assert!(parse(&["--cipher", "1301", "--max-tls", "1.2"]).tls.validate().is_err());
        assert!(parse(&["--cipher", "C02F", "--min-tls", "1.3"]).tls.validate().is_err());
    }

    #[test]
    fn legacy_versions_need_the_flag() {
        for args in [
            &["--min-tls", "1.0"][..],
            &["--max-tls", "1.1"],
            &["--min-tls", "1.1", "--max-tls", "1.2"],
        ] {
            assert!(parse(args).tls.validate().is_err(), "{args:?}");
            let with_flag: Vec<&str> = args.iter().copied().chain(["--allow-legacy-tls"]).collect();
            assert!(parse(&with_flag).tls.validate().is_ok(), "{with_flag:?}");
        }
    }

    #[test]
    fn the_legacy_flag_lowers_the_floor_and_the_security_level() {
        let plain = probe_settings(&["--allow-legacy-tls"]);
        assert_eq!(plain.min_tls, Some(TlsVersionArg::Tls1_0));
        assert_eq!(plain.cipher_list.as_deref(), Some("DEFAULT:@SECLEVEL=0"));
        let pinned = probe_settings(&["--allow-legacy-tls", "--min-tls", "1.1", "--cipher-list", "AES128-SHA"]);
        assert_eq!(pinned.min_tls, Some(TlsVersionArg::Tls1_1));
        assert_eq!(pinned.cipher_list.as_deref(), Some("AES128-SHA:@SECLEVEL=0"));
        let off = probe_settings(&["--min-tls", "1.2"]);
        assert_eq!(off.cipher_list, None);
    }

    #[test]
    fn cipher_rejects_unknown_and_unimplemented_suites_and_raw_lists() {
        let parse_err = |args: &[&str]| {
            Harness::try_parse_from(std::iter::once("dcert").chain(args.iter().copied()))
                .expect_err("rejected")
                .to_string()
        };
        assert!(parse_err(&["--cipher", "ECDHE-RSA-AES128-GCM-SHA265"]).contains("did you mean"));
        assert!(parse_err(&["--cipher", "TLS_NULL_WITH_NULL_NULL"]).contains("no OpenSSL implementation"));
        assert!(parse_err(&["--cipher", "C02F", "--cipher-list", "HIGH"]).contains("cannot be used with"));
    }

    #[test]
    fn explicit_flags_beat_the_profile_in_the_probe() {
        let parsed = parse(&[
            "--tls-profile",
            "intermediate",
            "--min-tls",
            "1.3",
            "--sni",
            "front.example",
            "--ca-cert",
            "ca.pem",
            "--timeout",
            "7",
        ]);
        let probe =
            ProbeOptions::new(&parsed.tls, &parsed.connection, ClientIdentity::default(), true).expect("valid options");
        let tls = probe.tls_probe();
        assert_eq!(tls.min_tls, Some(TlsVersionArg::Tls1_3));
        assert!(tls.cipher_list.is_some(), "the profile still supplies the TLS 1.2 list");
        assert_eq!(tls.sni_override, Some("front.example"));
        assert_eq!(tls.ca_cert_path, Some("ca.pem"));
        assert_eq!(tls.timeout_secs, 7);
        assert!(tls.debug);
    }

    #[test]
    fn an_inverted_version_range_is_rejected() {
        let parsed = parse(&["--min-tls", "1.3", "--max-tls", "1.2"]);
        let err = ProbeOptions::new(&parsed.tls, &parsed.connection, ClientIdentity::default(), false)
            .expect_err("min above max");
        assert!(err.to_string().contains("must not be greater"), "{err}");
    }

    #[test]
    fn overrides_reach_the_probe() {
        let parsed = parse(&["--resolve", "api.example.com:443:127.0.0.1"]);
        let probe = ProbeOptions::new(&parsed.tls, &parsed.connection, ClientIdentity::default(), false)
            .expect("valid options");
        assert!(
            probe
                .tls_probe()
                .connect_overrides
                .lookup("api.example.com", 443)
                .is_some()
        );
    }
}
