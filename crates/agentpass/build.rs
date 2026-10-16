//! Embeds the prebuilt Yew web UI (`ui/`, produced by `just web`) into the
//! binary. The UI is committed so `cargo install --git …` needs no trunk or
//! wasm toolchain.
//!
//! `ui/.source-hash` records a hash of the web UI sources it was built from.
//! When the sources are present (a git checkout) and the hash differs, the
//! build warns, or fails if `AGENTPASS_REQUIRE_FRESH_UI=1` (CI). `just web`
//! sets `AGENTPASS_WRITE_UI_HASH=1` to record the hash after rebuilding.
//! `AGENTPASS_WEB_DIST` embeds another directory instead.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else if entry.file_name() != ".source-hash" {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn collect(root: &Path, rel: &Path, out: &mut Vec<PathBuf>) {
    let path = root.join(rel);
    if path.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(&path).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            collect(root, &rel.join(e.file_name()), out);
        }
    } else if path.is_file() {
        out.push(rel.to_owned());
    }
}

/// Hash of everything the web UI is built from, or `None` outside a checkout.
fn source_hash(crates: &Path) -> Option<String> {
    if !crates.join("web/src/main.rs").is_file() {
        return None;
    }
    let inputs = [
        "web/src",
        "web/js",
        "web/index.html",
        "web/style.css",
        "web/favicon.svg",
        "web/Cargo.toml",
        "web/Trunk.toml",
        "protocol/src",
        "protocol/Cargo.toml",
    ];
    let mut files = Vec::new();
    for i in inputs {
        collect(crates, Path::new(i), &mut files);
    }
    let mut h = Sha256::new();
    for f in &files {
        println!("cargo:rerun-if-changed={}", crates.join(f).display());
        let text = f.to_string_lossy().replace('\\', "/");
        h.update(text.as_bytes());
        h.update([0]);
        // Normalise line endings so checkouts with CRLF hash the same.
        let body = std::fs::read(crates.join(f)).unwrap();
        let body: Vec<u8> = body.into_iter().filter(|&b| b != b'\r').collect();
        h.update(&body);
        h.update([0]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("web");
    for var in [
        "AGENTPASS_WEB_DIST",
        "AGENTPASS_REQUIRE_FRESH_UI",
        "AGENTPASS_WRITE_UI_HASH",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    let custom = std::env::var_os("AGENTPASS_WEB_DIST").map(PathBuf::from);
    let ui = custom.clone().unwrap_or_else(|| manifest.join("ui"));
    println!("cargo:rerun-if-changed={}", ui.display());

    let _ = std::fs::remove_dir_all(&out);
    if ui.join("index.html").is_file() {
        copy_dir(&ui, &out).expect("copying web UI");
        let mut stack = vec![ui.clone()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                println!("cargo:rerun-if-changed={}", e.path().display());
                if e.path().is_dir() {
                    stack.push(e.path());
                }
            }
        }
    } else {
        println!(
            "cargo:warning=web UI missing ({} not found); run `just web`. Embedding a placeholder.",
            ui.join("index.html").display()
        );
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            out.join("index.html"),
            "<!doctype html><meta charset=utf-8><title>agentpass</title>\
             <p>This agentpass binary was built without its web UI. Rebuild with <code>just build</code>.</p>",
        )
        .unwrap();
    }

    if custom.is_some() {
        return;
    }
    if let Some(hash) = source_hash(&manifest.join("..")) {
        let recorded_path = ui.join(".source-hash");
        if std::env::var_os("AGENTPASS_WRITE_UI_HASH").is_some() {
            std::fs::write(&recorded_path, format!("{hash}\n")).expect("writing ui/.source-hash");
            return;
        }
        let recorded = std::fs::read_to_string(&recorded_path).unwrap_or_default();
        if recorded.trim() != hash {
            let msg = "the committed web UI (crates/agentpass/ui) is older than its sources; run `just web` and commit the result";
            if std::env::var_os("AGENTPASS_REQUIRE_FRESH_UI").is_some() {
                panic!("{msg}");
            }
            println!("cargo:warning={msg}");
        }
    }
}
