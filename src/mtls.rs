//! Client certificate (mutual TLS) detection.
//!
//! A server that wants a client certificate says so with a CertificateRequest
//! message in the handshake. What happens next depends on the server policy
//! and on the TLS version: a TLS 1.2 server that requires a certificate
//! usually aborts with a generic `handshake_failure` alert, and a TLS 1.3
//! server sends `certificate_required` only after the client's Finished, so
//! the client's `connect()` succeeds and the alert surfaces on the first read.
//! Matching alert text therefore misses most TLS 1.3 mTLS endpoints (Envoy,
//! Istio, Apigee hybrid ingress, nginx, CloudFront), and it can never see a
//! server that only asks for a certificate optionally.
//!
//! [`install`] registers an OpenSSL certificate callback (`SSL_CTX_set_cert_cb`)
//! that fires exactly when a CertificateRequest arrives, whether or not a
//! client identity is configured. It records that fact and the acceptable CA
//! names the server listed, then lets the handshake continue unchanged.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, OnceLock};

use openssl::ex_data::Index;
use openssl::ssl::{SslContext, SslContextBuilder, SslRef};

/// What the probe learned about client certificate authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthStatus {
    /// The server never sent a CertificateRequest: not an mTLS endpoint.
    #[default]
    NotRequested,
    /// The server asked for a certificate, none was supplied, and the request
    /// still went through: mTLS in optional (verify on request) mode.
    Optional,
    /// The server asked for a certificate and refused the connection without
    /// one: mTLS in required mode.
    Required,
    /// The server asked for a certificate and the configured one was sent.
    Presented,
}

impl ClientAuthStatus {
    /// Human readable label used in pretty output.
    pub fn label(self) -> &'static str {
        match self {
            ClientAuthStatus::NotRequested => "not requested",
            ClientAuthStatus::Optional => "requested (optional)",
            ClientAuthStatus::Required => "required",
            ClientAuthStatus::Presented => "requested, client certificate sent",
        }
    }
}

/// Details of the server's CertificateRequest, when one arrived.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertRequest {
    /// `true` once the server sent a CertificateRequest.
    pub requested: bool,
    /// Distinguished names of the CAs the server says it accepts. Often
    /// empty: many gateways (Envoy among them) send no list at all.
    pub acceptable_cas: Vec<String>,
}

/// Shared slot the OpenSSL callback writes into. One per connector, so
/// concurrent probes never see each other's state.
#[derive(Debug, Clone, Default)]
pub struct CertRequestCapture {
    inner: Arc<Mutex<CertRequest>>,
}

impl CertRequestCapture {
    /// Snapshot of what the callback recorded so far.
    pub fn get(&self) -> CertRequest {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn record(&self, acceptable_cas: Vec<String>) {
        let mut slot = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.requested = true;
        slot.acceptable_cas = acceptable_cas;
    }
}

/// A handshake or post handshake failure after the server had asked for a
/// client certificate. Carried as the error value so the diagnostics engine
/// can read the request from a failed probe; `Display` is the original text.
#[derive(Debug)]
pub struct CertRequestedError {
    pub message: String,
    pub acceptable_cas: Vec<String>,
}

impl std::fmt::Display for CertRequestedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CertRequestedError {}

fn capture_index() -> Option<Index<SslContext, CertRequestCapture>> {
    static INDEX: OnceLock<Option<Index<SslContext, CertRequestCapture>>> = OnceLock::new();
    *INDEX.get_or_init(|| SslContext::new_ex_index().ok())
}

/// Register the CertificateRequest callback on `builder` and return the slot
/// it fills. If OpenSSL cannot allocate the ex data index the returned
/// capture simply stays empty and detection falls back to alert text.
pub fn install(builder: &mut SslContextBuilder) -> CertRequestCapture {
    let capture = CertRequestCapture::default();
    if let Some(index) = capture_index() {
        builder.set_ex_data(index, capture.clone());
        ffi::set_cert_cb(builder.as_ptr());
    }
    capture
}

/// Called from the OpenSSL callback with the live SSL handle.
fn on_cert_request(ssl: &SslRef, acceptable_cas: Vec<String>) {
    if let Some(index) = capture_index()
        && let Some(capture) = ssl.ssl_context().ex_data(index)
    {
        capture.record(acceptable_cas);
    }
}

/// The two libssl entry points the openssl crate does not wrap. Both have
/// existed since OpenSSL 1.0.2, so no version gate is needed.
#[allow(unsafe_code)]
mod ffi {
    use foreign_types::ForeignTypeRef;
    use openssl::ssl::SslRef;
    use openssl::stack::StackRef;
    use openssl::x509::X509Name;
    use std::ffi::{c_int, c_void};

    type CertCb = unsafe extern "C" fn(*mut openssl_sys::SSL, *mut c_void) -> c_int;

    unsafe extern "C" {
        fn SSL_CTX_set_cert_cb(ctx: *mut openssl_sys::SSL_CTX, cb: Option<CertCb>, arg: *mut c_void);
        fn SSL_get_client_CA_list(ssl: *const openssl_sys::SSL) -> *mut openssl_sys::stack_st_X509_NAME;
    }

    pub(super) fn set_cert_cb(ctx: *mut openssl_sys::SSL_CTX) {
        // SAFETY: `ctx` comes from a live SslContextBuilder that the caller
        // still borrows mutably. The callback is a plain function with the
        // signature libssl expects and it ignores `arg`, so passing null is
        // fine and there is no lifetime to manage.
        unsafe { SSL_CTX_set_cert_cb(ctx, Some(cert_cb), std::ptr::null_mut()) }
    }

    /// Runs inside the handshake when a CertificateRequest has been received
    /// (on the client, libssl calls the cert callback only then). Returning 1
    /// tells libssl to continue with whatever identity is already configured.
    unsafe extern "C" fn cert_cb(ssl: *mut openssl_sys::SSL, _arg: *mut c_void) -> c_int {
        if ssl.is_null() {
            return 1;
        }
        // Never unwind into C: any panic in the recording path is dropped.
        let _ = std::panic::catch_unwind(|| {
            // SAFETY: libssl passes the SSL handle the handshake is running
            // on; it outlives this call and is not used concurrently.
            let ssl_ref = unsafe { SslRef::from_ptr(ssl) };
            // SAFETY: on a client SSL_get_client_CA_list returns the CA list
            // received in the CertificateRequest (or null). The stack is owned
            // by the SSL object and only borrowed for the copy below.
            let list = unsafe { SSL_get_client_CA_list(ssl) };
            let names = if list.is_null() {
                Vec::new()
            } else {
                // SAFETY: non null pointer to a STACK_OF(X509_NAME) owned by `ssl`.
                let stack: &StackRef<X509Name> = unsafe { StackRef::from_ptr(list) };
                stack.iter().map(crate::cert::format_x509_name).collect()
            };
            super::on_cert_request(ssl_ref, names);
        });
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_starts_empty_and_records_requests() {
        let capture = CertRequestCapture::default();
        assert_eq!(capture.get(), CertRequest::default());
        capture.record(vec!["CN=Client CA".to_string()]);
        let got = capture.get();
        assert!(got.requested);
        assert_eq!(got.acceptable_cas, vec!["CN=Client CA".to_string()]);
    }

    #[test]
    fn install_registers_on_a_real_context() {
        let mut builder = SslContext::builder(openssl::ssl::SslMethod::tls()).expect("ctx");
        let capture = install(&mut builder);
        assert!(!capture.get().requested);
    }

    #[test]
    fn status_serialises_snake_case() {
        let json = serde_json::to_string(&ClientAuthStatus::NotRequested).unwrap();
        assert_eq!(json, "\"not_requested\"");
        assert_eq!(ClientAuthStatus::Required.label(), "required");
    }

    #[test]
    fn error_displays_the_original_message() {
        let e = CertRequestedError {
            message: "TLS handshake failed: tlsv1 alert unknown ca".to_string(),
            acceptable_cas: Vec::new(),
        };
        assert_eq!(e.to_string(), "TLS handshake failed: tlsv1 alert unknown ca");
    }
}
