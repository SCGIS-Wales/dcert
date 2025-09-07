use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Always rerun if Cargo.lock changes
    println!("cargo:rerun-if-changed=Cargo.lock");
    let lock_path = PathBuf::from("Cargo.lock");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = out_dir.join("deps.rs");

    let deps_str = if let Ok(lock) = fs::read_to_string(&lock_path) {
        match toml::from_str::<toml::Table>(&lock) {
            Ok(tbl) => {
                if let Some(packages) = tbl.get("package").and_then(|v| v.as_array()) {
                    let mut parts: Vec<String> = Vec::new();
                    for p in packages {
                        let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
                        if !name.is_empty() && !version.is_empty() {
                            parts.push(format!("{} {}", name, version));
                        }
                    }
                    parts.sort();
                    parts.join("\n")
                } else {
                    String::new()
                }
            }
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };

    let contents = format!(
        "pub const PKG_VERSION: &str = \"{}\";\n         pub const DEP_VERSIONS: &str = r#\"{}\"#;\n",
        env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into()),
        deps_str
    );
    fs::write(&out_file, contents).unwrap();
}
