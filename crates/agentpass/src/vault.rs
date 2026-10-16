//! The `agentpass.toml` vault file. Only secret values (and wrapped private
//! keys) are encrypted; everything else is plain text so the file can be
//! reviewed and committed to git.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, KEY_LEN};

pub const FILE_NAME: &str = "agentpass.toml";
pub const VERSION: u32 = 1;

const HEADER: &str = "# agentpass vault: https://github.com/traumventures/agentpass\n\
# Secret values are encrypted; keys and descriptions are plain text.\n\
# This file is safe to commit. Edit it with the `agentpass` CLI.\n\n";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub vault_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// X25519 public key (base64).
    pub public_key: String,
    #[serde(default)]
    pub passkeys: Vec<PasskeyEntry>,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasskeyEntry {
    pub label: String,
    /// WebAuthn credential id (base64url).
    pub credential_id: String,
    /// PRF input for this passkey (base64url).
    pub prf_salt: String,
    /// Vault private key wrapped with this passkey's PRF output.
    pub wrapped_private_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Vault {
    pub path: PathBuf,
    pub file: VaultFile,
}

impl Vault {
    pub fn load(path: &Path) -> Result<Self> {
        let path = absolute(path)?;
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading vault {}", path.display()))?;
        let file: VaultFile =
            toml::from_str(&text).with_context(|| format!("parsing vault {}", path.display()))?;
        if file.version != VERSION {
            bail!(
                "{} has vault version {}, this agentpass supports version {VERSION}",
                path.display(),
                file.version
            );
        }
        let v = Self { path, file };
        v.public_key()?;
        Ok(v)
    }

    pub fn public_key(&self) -> Result<[u8; KEY_LEN]> {
        crypto::from_b64(&self.file.public_key)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow!("{}: invalid public_key", self.path.display()))
    }

    pub fn name(&self) -> String {
        self.file
            .name
            .clone()
            .unwrap_or_else(|| default_name(&self.path))
    }

    pub fn id(&self) -> &str {
        &self.file.vault_id
    }

    /// Writes the vault atomically (temp file + rename in the same directory).
    pub fn save(&self) -> Result<()> {
        write_atomic(&self.path, &self.file)
    }

    pub fn set_secret(
        &mut self,
        key: &str,
        value: &[u8],
        description: Option<String>,
    ) -> Result<()> {
        validate_key_name(key)?;
        let sealed = crypto::seal_value(&self.public_key()?, self.id(), key, value)?;
        let description = description.or_else(|| {
            self.file
                .secrets
                .get(key)
                .and_then(|s| s.description.clone())
        });
        self.file.secrets.insert(
            key.to_owned(),
            SecretEntry {
                description: description.filter(|d| !d.is_empty()),
                value: sealed,
            },
        );
        Ok(())
    }

    pub fn passkey(&self, credential_id: &str) -> Option<&PasskeyEntry> {
        self.file
            .passkeys
            .iter()
            .find(|p| p.credential_id == credential_id)
    }
}

pub fn write_atomic(path: &Path, file: &VaultFile) -> Result<()> {
    let body = toml::to_string(file).context("serialising vault")?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(FILE_NAME),
        std::process::id()
    ));
    let result = (|| -> Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(HEADER.as_bytes())?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing vault {}", path.display()))
}

pub fn default_name(path: &Path) -> String {
    path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("agentpass")
        .to_owned()
}

pub fn absolute(path: &Path) -> Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    // Canonicalise the directory (the file itself may not exist yet).
    match (abs.parent(), abs.file_name()) {
        (Some(dir), Some(name)) if dir.exists() => Ok(dir.canonicalize()?.join(name)),
        _ => Ok(abs),
    }
}

/// Finds the vault: explicit path (flag or `AGENTPASS_VAULT`), otherwise the
/// nearest `agentpass.toml` in the current directory or a parent.
pub fn locate(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        let p = if p.is_dir() {
            p.join(FILE_NAME)
        } else {
            p.to_owned()
        };
        return absolute(&p);
    }
    let cwd = std::env::current_dir()?;
    for dir in cwd.ancestors() {
        let candidate = dir.join(FILE_NAME);
        if candidate.is_file() {
            return absolute(&candidate);
        }
    }
    bail!(
        "no {FILE_NAME} found in {} or its parents; run `agentpass setup` or pass --vault",
        cwd.display()
    )
}

/// Path for a new vault: explicit path or `./agentpass.toml`.
pub fn new_vault_path(explicit: Option<&Path>) -> Result<PathBuf> {
    match explicit {
        Some(p) if p.is_dir() => absolute(&p.join(FILE_NAME)),
        Some(p) => absolute(p),
        None => absolute(Path::new(FILE_NAME)),
    }
}

/// Secret names: letters, digits, `_`, `.` and `-`; must not start with `.`
/// or `-`.
pub fn validate_key_name(key: &str) -> Result<()> {
    let ok = !key.is_empty()
        && key.len() <= 128
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && !key.starts_with(['.', '-']);
    if ok {
        Ok(())
    } else {
        bail!("invalid secret name {key:?}: use letters, digits, '_', '.', '-' (max 128 chars)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;

    fn new_vault(dir: &Path) -> (Vault, PrivateKey) {
        let key = PrivateKey::generate().unwrap();
        let file = VaultFile {
            version: VERSION,
            vault_id: "01TEST".into(),
            name: None,
            public_key: crypto::b64(&key.public_key()),
            passkeys: vec![PasskeyEntry {
                label: "test".into(),
                credential_id: "cred".into(),
                prf_salt: "salt".into(),
                wrapped_private_key: crypto::wrap_private_key(&key, &[1; 32], "01TEST", "cred")
                    .unwrap(),
                created: None,
            }],
            secrets: BTreeMap::new(),
        };
        let path = dir.join(FILE_NAME);
        write_atomic(&path, &file).unwrap();
        (Vault::load(&path).unwrap(), key)
    }

    #[test]
    fn file_is_readable_toml_with_only_values_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let (mut v, key) = new_vault(dir.path());
        v.set_secret("GITHUB_TOKEN", b"ghp_supersecret", Some("CI token".into()))
            .unwrap();
        v.save().unwrap();
        let text = std::fs::read_to_string(&v.path).unwrap();
        assert!(text.starts_with("# agentpass vault"));
        assert!(text.contains("[secrets.GITHUB_TOKEN]"));
        assert!(text.contains("description = \"CI token\""));
        assert!(!text.contains("ghp_supersecret"));
        let v2 = Vault::load(&v.path).unwrap();
        let entry = &v2.file.secrets["GITHUB_TOKEN"];
        let plain = crypto::open_value(
            &key,
            &v2.public_key().unwrap(),
            v2.id(),
            "GITHUB_TOKEN",
            &entry.value,
        )
        .unwrap();
        assert_eq!(plain.as_slice(), b"ghp_supersecret");
    }

    #[test]
    fn set_keeps_description_unless_given() {
        let dir = tempfile::tempdir().unwrap();
        let (mut v, _) = new_vault(dir.path());
        v.set_secret("A", b"1", Some("first".into())).unwrap();
        v.set_secret("A", b"2", None).unwrap();
        assert_eq!(v.file.secrets["A"].description.as_deref(), Some("first"));
        v.set_secret("A", b"3", Some(String::new())).unwrap();
        assert_eq!(v.file.secrets["A"].description, None);
    }

    #[test]
    fn locate_walks_up() {
        let dir = tempfile::tempdir().unwrap();
        let (v, _) = new_vault(dir.path());
        let sub = dir.path().join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&sub).unwrap();
        let found = locate(None);
        std::env::set_current_dir(prev).unwrap();
        assert_eq!(found.unwrap(), v.path);
        assert_eq!(locate(Some(dir.path())).unwrap(), v.path);
    }

    #[test]
    fn key_names() {
        for ok in ["A", "GITHUB_TOKEN", "db.password", "x-1"] {
            validate_key_name(ok).unwrap();
        }
        for bad in ["", ".a", "-a", "a b", "a=b", "ä", &"x".repeat(129)] {
            assert!(validate_key_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_unknown_version() {
        let dir = tempfile::tempdir().unwrap();
        let (v, _) = new_vault(dir.path());
        let text = std::fs::read_to_string(&v.path)
            .unwrap()
            .replace("version = 1", "version = 2");
        std::fs::write(&v.path, text).unwrap();
        assert!(Vault::load(&v.path).is_err());
    }
}
