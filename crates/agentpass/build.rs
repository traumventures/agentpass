//! Embeds the Yew web UI (`crates/web/dist`, built with `trunk build`) into
//! the binary. Set `AGENTPASS_WEB_DIST` to use another directory. Without a
//! built UI a placeholder page is embedded and a warning is printed.

use std::path::{Path, PathBuf};

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("web");
    println!("cargo:rerun-if-env-changed=AGENTPASS_WEB_DIST");
    let dist = std::env::var_os("AGENTPASS_WEB_DIST")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../web/dist"));
    println!("cargo:rerun-if-changed={}", dist.display());
    let _ = std::fs::remove_dir_all(&out);
    if dist.join("index.html").is_file() {
        copy_dir(&dist, &out).expect("copying web UI");
        // Track individual files so rebuilding the UI re-embeds it.
        for entry in std::fs::read_dir(&dist).unwrap().flatten() {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    } else {
        println!(
            "cargo:warning=web UI not built ({} missing); run `just web` (trunk build) first. Embedding a placeholder.",
            dist.join("index.html").display()
        );
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            out.join("index.html"),
            "<!doctype html><meta charset=utf-8><title>agentpass</title>\
             <p>This agentpass binary was built without its web UI. \
             Rebuild with <code>just build</code>.</p>",
        )
        .unwrap();
    }
}
