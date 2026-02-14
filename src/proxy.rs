use anyhow::Result;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use url::Url;

use crate::tls::{CONNECTION_TIMEOUT_SECS, READ_TIMEOUT_SECS};

/// Cached proxy configuration, read once at startup.
pub struct ProxyConfig {
    pub https_proxy: Option<String>,
    pub http_proxy: Option<String>,
    pub no_proxy: String,
}

impl ProxyConfig {
    pub fn from_env() -> Self {
        let https_proxy = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
            .iter()
            .find_map(|var| env::var(var).ok().filter(|v| !v.is_empty()));
        let http_proxy = ["HTTP_PROXY", "http_proxy"]
            .iter()
            .find_map(|var| env::var(var).ok().filter(|v| !v.is_empty()));
        let no_proxy = env::var("no_proxy")
            .or_else(|_| env::var("NO_PROXY"))
            .unwrap_or_default();
        Self {
            https_proxy,
            http_proxy,
            no_proxy,
        }
    }

    pub fn get_proxy_url(&self, scheme: &str) -> Option<&str> {
        match scheme {
            "https" => self.https_proxy.as_deref(),
            "http" => self.http_proxy.as_deref(),
            _ => None,
        }
    }

    pub fn should_bypass(&self, host: &str) -> bool {
        if self.no_proxy.is_empty() {
            return false;
        }
        let host = host.to_lowercase();
        for pattern in self.no_proxy.split(',') {
            let pattern = pattern.trim().to_lowercase();
            if pattern.is_empty() {
                continue;
            }
            if pattern == host {
                return true;
            }
            if pattern.starts_with('.') && host.ends_with(&pattern) {
                return true;
            }
            if !pattern.starts_with('.') && host.ends_with(&format!(".{}", pattern)) {
                return true;
            }
            if pattern == "localhost" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
                return true;
            }
        }
        false
    }
}

/// Connect through HTTP proxy using CONNECT method
pub fn connect_through_proxy(proxy_url: &str, target_host: &str, target_port: u16) -> Result<TcpStream> {
    let proxy = Url::parse(proxy_url).map_err(|e| anyhow::anyhow!("Invalid proxy URL {}: {}", proxy_url, e))?;

    let proxy_host = proxy
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Proxy URL must include a host"))?;
    let proxy_port = proxy.port().unwrap_or(8080);

    // Connect to proxy
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port)
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("Failed to resolve proxy {}: {}", proxy_host, e))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No valid address found for proxy {}", proxy_host))?;

    let mut stream = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(CONNECTION_TIMEOUT_SECS))
        .map_err(|e| anyhow::anyhow!("Failed to connect to proxy: {}", e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
        .map_err(|e| anyhow::anyhow!("Failed to set proxy read timeout: {}", e))?;

    // Send CONNECT request
    let connect_request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: keep-alive\r\n\r\n",
        target_host, target_port, target_host, target_port
    );

    stream
        .write_all(connect_request.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to send CONNECT request: {}", e))?;

    // Read proxy response
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];

    // Read until we get the full HTTP response headers
    loop {
        let n = stream
            .read(&mut buffer)
            .map_err(|e| anyhow::anyhow!("Failed to read proxy response: {}", e))?;

        if n == 0 {
            break;
        }

        response.extend_from_slice(&buffer[..n]);

        // Check if we have the complete headers (ending with \r\n\r\n)
        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    let status_line = response_str
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty proxy response"))?;

    // Check if the CONNECT was successful (HTTP/x.x 200 ...)
    let status_ok = status_line
        .split_whitespace()
        .nth(1)
        .map(|code| code == "200")
        .unwrap_or(false);
    if !status_ok {
        return Err(anyhow::anyhow!("Proxy CONNECT failed: {}", status_line));
    }

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // ProxyConfig::should_bypass tests
    // ---------------------------------------------------------------

    #[test]
    fn test_bypass_proxy_logic() {
        let empty = ProxyConfig {
            https_proxy: None,
            http_proxy: None,
            no_proxy: String::new(),
        };
        assert!(!empty.should_bypass("example.com"), "empty no_proxy should not bypass");

        let exact = ProxyConfig {
            https_proxy: None,
            http_proxy: None,
            no_proxy: "example.com,other.com".to_string(),
        };
        assert!(exact.should_bypass("example.com"), "exact match should bypass");
        assert!(exact.should_bypass("other.com"), "exact match should bypass");
        assert!(!exact.should_bypass("notmatched.com"), "non-matching should not bypass");

        let suffix = ProxyConfig {
            https_proxy: None,
            http_proxy: None,
            no_proxy: ".example.com".to_string(),
        };
        assert!(
            suffix.should_bypass("sub.example.com"),
            "suffix should bypass subdomain"
        );
        assert!(
            !suffix.should_bypass("example.com"),
            "suffix should not bypass exact domain"
        );

        let subdomain = ProxyConfig {
            https_proxy: None,
            http_proxy: None,
            no_proxy: "example.com".to_string(),
        };
        assert!(subdomain.should_bypass("sub.example.com"), "subdomain should bypass");

        let localhost = ProxyConfig {
            https_proxy: None,
            http_proxy: None,
            no_proxy: "localhost".to_string(),
        };
        assert!(localhost.should_bypass("localhost"), "localhost should bypass");
        assert!(
            localhost.should_bypass("127.0.0.1"),
            "127.0.0.1 should bypass for localhost"
        );
        assert!(localhost.should_bypass("::1"), "::1 should bypass for localhost");
    }

    // ---------------------------------------------------------------
    // ProxyConfig::get_proxy_url tests
    // ---------------------------------------------------------------

    #[test]
    fn test_get_proxy_url_logic() {
        let empty = ProxyConfig {
            https_proxy: None,
            http_proxy: None,
            no_proxy: String::new(),
        };
        assert_eq!(empty.get_proxy_url("https"), None, "no proxy should return None");
        assert_eq!(empty.get_proxy_url("http"), None, "no proxy should return None");
        assert_eq!(empty.get_proxy_url("ftp"), None, "unknown scheme should return None");

        let with_https = ProxyConfig {
            https_proxy: Some("http://proxy:8080".to_string()),
            http_proxy: None,
            no_proxy: String::new(),
        };
        assert_eq!(
            with_https.get_proxy_url("https"),
            Some("http://proxy:8080"),
            "https should use https_proxy"
        );
        assert_eq!(
            with_https.get_proxy_url("http"),
            None,
            "http should not use https_proxy"
        );

        let with_http = ProxyConfig {
            https_proxy: None,
            http_proxy: Some("http://httpproxy:3128".to_string()),
            no_proxy: String::new(),
        };
        assert_eq!(
            with_http.get_proxy_url("http"),
            Some("http://httpproxy:3128"),
            "http should use http_proxy"
        );
    }
}
