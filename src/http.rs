//! Shared construction of blocking HTTP clients.
//!
//! Every outbound HTTP call that is not the TLS probe itself (AIA issuer
//! fetches, public root refreshes, Vault) goes through [`blocking_client`],
//! so proxy handling, timeouts, custom CA material and the user agent are
//! configured in exactly one place.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::proxy::ProxyConfig;

/// User agent sent by every reqwest client built here.
pub const USER_AGENT: &str = concat!("dcert/", env!("CARGO_PKG_VERSION"));

/// Options for [`blocking_client`].
#[derive(Debug, Clone, Default)]
pub struct HttpClientOptions<'a> {
    /// Overall request timeout. `None` keeps reqwest's default (no timeout).
    pub timeout: Option<Duration>,
    /// TCP connect timeout. Defaults to `timeout` when unset.
    pub connect_timeout: Option<Duration>,
    /// Forward proxy configuration. `None` disables proxy support entirely
    /// (reqwest's own environment sniffing is switched off so behaviour is
    /// identical to dcert's TLS path).
    pub proxy: Option<&'a ProxyConfig>,
    /// Disable server certificate verification. Callers must warn the user.
    pub accept_invalid_certs: bool,
    /// Extra root certificate bundle (PEM, may contain several certificates).
    pub ca_file: Option<&'a str>,
    /// Directory of `.pem`, `.crt` or `.cer` files to add as roots.
    pub ca_dir: Option<&'a str>,
}

/// Number of CA certificates loaded from a directory by [`blocking_client`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaDirSummary {
    pub loaded: usize,
}

/// Build a blocking reqwest client from `opts`.
pub fn blocking_client(opts: &HttpClientOptions<'_>) -> Result<reqwest::blocking::Client> {
    let (client, _) = blocking_client_with_summary(opts)?;
    Ok(client)
}

/// Same as [`blocking_client`] but also reports how many CA files were loaded
/// from `ca_dir`, for debug output.
pub fn blocking_client_with_summary(opts: &HttpClientOptions<'_>) -> Result<(reqwest::blocking::Client, CaDirSummary)> {
    let mut builder = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(opts.accept_invalid_certs);

    if let Some(t) = opts.timeout {
        builder = builder.timeout(t).connect_timeout(opts.connect_timeout.unwrap_or(t));
    } else if let Some(c) = opts.connect_timeout {
        builder = builder.connect_timeout(c);
    }

    match opts.proxy {
        Some(proxy) => {
            let no_proxy = reqwest::NoProxy::from_string(&proxy.no_proxy);
            if let Some(p) = &proxy.https_proxy {
                builder = builder.proxy(
                    reqwest::Proxy::https(p)
                        .map_err(|e| anyhow::anyhow!("invalid https proxy '{p}': {e}"))?
                        .no_proxy(no_proxy.clone()),
                );
            }
            if let Some(p) = &proxy.http_proxy {
                builder = builder.proxy(
                    reqwest::Proxy::http(p)
                        .map_err(|e| anyhow::anyhow!("invalid http proxy '{p}': {e}"))?
                        .no_proxy(no_proxy),
                );
            }
        }
        None => {
            builder = builder.no_proxy();
        }
    }

    if let Some(path) = opts.ca_file {
        for cert in load_ca_file(path)? {
            builder = builder.add_root_certificate(cert);
        }
    }

    let mut summary = CaDirSummary::default();
    if let Some(dir) = opts.ca_dir {
        for cert in load_ca_dir(dir)? {
            builder = builder.add_root_certificate(cert);
            summary.loaded += 1;
        }
    }

    let client = builder.build().context("failed to build HTTP client")?;
    Ok((client, summary))
}

/// Parse every certificate in a PEM bundle.
pub fn load_ca_file(path: &str) -> Result<Vec<reqwest::Certificate>> {
    let pem = fs::read(path).with_context(|| format!("Failed to read CA certificate file: {path}"))?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem)
        .with_context(|| format!("Failed to parse CA certificate from: {path}"))?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in CA file: {path}");
    }
    Ok(certs)
}

/// Load every `.pem`, `.crt` or `.cer` file in `dir` as a root certificate.
/// Files that fail to parse are skipped so one stray file does not disable
/// the whole directory.
pub fn load_ca_dir(dir: &str) -> Result<Vec<reqwest::Certificate>> {
    let mut certs = Vec::new();
    let entries = fs::read_dir(dir).with_context(|| format!("Failed to read CA path directory: {dir}"))?;
    for entry in entries {
        let path = entry?.path();
        if !is_ca_file(&path) {
            continue;
        }
        if let Ok(pem) = fs::read(&path)
            && let Ok(parsed) = reqwest::Certificate::from_pem_bundle(&pem)
        {
            certs.extend(parsed);
        }
    }
    Ok(certs)
}

fn is_ca_file(path: &Path) -> bool {
    matches!(path.extension().and_then(|e| e.to_str()), Some("pem" | "crt" | "cer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds_without_proxy() {
        let opts = HttpClientOptions {
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };
        assert!(blocking_client(&opts).is_ok());
    }

    #[test]
    fn client_rejects_invalid_proxy_url() {
        let proxy = ProxyConfig {
            https_proxy: Some("not a url".to_string()),
            http_proxy: None,
            no_proxy: String::new(),
        };
        let opts = HttpClientOptions {
            proxy: Some(&proxy),
            ..Default::default()
        };
        let err = blocking_client(&opts).unwrap_err().to_string();
        assert!(err.contains("invalid https proxy"), "{err}");
    }

    #[test]
    fn ca_dir_skips_unparseable_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("junk.pem"), "not a certificate").unwrap();
        fs::write(dir.path().join("ignored.txt"), "x").unwrap();
        let certs = load_ca_dir(dir.path().to_str().unwrap()).unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn ca_file_reports_missing_file() {
        let err = load_ca_file("/definitely/missing.pem").unwrap_err().to_string();
        assert!(err.contains("Failed to read CA certificate file"), "{err}");
    }

    #[test]
    fn ca_file_reports_empty_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.pem");
        fs::write(&p, "").unwrap();
        let err = load_ca_file(p.to_str().unwrap()).unwrap_err().to_string();
        assert!(err.contains("No certificates found"), "{err}");
    }
}
