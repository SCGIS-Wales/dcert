use std::process::Command;

fn main() {
    // Re-run if git HEAD changes (new commit, tag, checkout, etc.)
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");

    // Try to get version from git describe (e.g. "v2.0.2" or "v2.0.2-3-gabcdef")
    let git_version = Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    if let Some(ver) = git_version {
        println!("cargo:rustc-env=DCERT_GIT_VERSION={ver}");
    }
}
