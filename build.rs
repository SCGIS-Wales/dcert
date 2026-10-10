//! Expose the linked OpenSSL version to the crate as `cfg` flags so code that
//! needs a newer libssl API (for example `SSL_get0_group_name`, OpenSSL 3.2+)
//! compiles against the OpenSSL 3.0 that Ubuntu 22.04/24.04 and Debian
//! bookworm still ship. `openssl-sys` publishes the number it detected through
//! its `links` metadata, which Cargo hands to this script as
//! `DEP_OPENSSL_VERSION_NUMBER`.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(dcert_ossl320)");
    println!("cargo:rustc-check-cfg=cfg(dcert_ossl350)");
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_VERSION_NUMBER");

    let Ok(raw) = std::env::var("DEP_OPENSSL_VERSION_NUMBER") else {
        return;
    };
    let Ok(version) = u64::from_str_radix(raw.trim(), 16) else {
        return;
    };
    // OPENSSL_VERSION_NUMBER layout: 0xMNN00PP0 (major, minor, patch).
    if version >= 0x3_02_00_00_0 {
        println!("cargo:rustc-cfg=dcert_ossl320");
    }
    if version >= 0x3_05_00_00_0 {
        println!("cargo:rustc-cfg=dcert_ossl350");
    }
}
