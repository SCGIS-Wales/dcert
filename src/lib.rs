//! Shared library for the `dcert` CLI and the `dcert-mcp` server.
//!
//! Both binaries link against this crate so that certificate parsing, TLS
//! probing, trust classification, Vault access and diagnostics live in one
//! place instead of being duplicated per binary.

pub mod cert;
pub mod cli;
pub mod compliance;
pub mod connect;
pub mod convert;
pub mod csr;
pub mod debug;
pub mod diagnose;
pub mod http;
pub mod kbref;
pub mod ocsp;
pub mod output;
pub mod proxy;
pub mod secret;
pub mod tls;
pub mod trust;
pub mod vault;
