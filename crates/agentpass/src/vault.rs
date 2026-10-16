//! Vault files (`<name>.agentpass.toml`, by default `secrets.agentpass.toml`). Only secret values (and wrapped private
//! keys) are encrypted; everything else is plain text so the file can be
//! reviewed and committed to git.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, KEY_LEN};

/// Every vault file name ends with this suffix.
pub const SUFFIX: &str = ".agentpass.toml";
/// File name used by `agentpass setup` unless told otherwise.
pub const DEFAULT_FILE: &str = "secrets.agentpass.toml";
/// File name used by agentpass 0.1.0; still found for compatibility.
const LEGACY_FILE: &str = "agentpass.toml";
pub const VERSION: u32 = 1;

const HEADER: &str = "# agentpass vault: https://github.com/traumventures/agentpass\n\
# Secret values are encrypted; keys and descriptions are plain text.\n\
# This file is safe to commit. Edit it with the `agentpass` CLI.\n\n";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub vault_id: String,
    /// Human-readable vault name, shown on the unlock page and in the CLI.
    /// (Optional when reading files written by agentpass 0.1.0.)
    #[serde(default)]
    pub name: String,
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
        let mut file: VaultFile =
            toml::from_str(&text).with_context(|| format!("parsing vault {}", path.display()))?;
        if file.name.trim().is_empty() {
            file.name = default_name(&path);
        }
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
        self.file.name.clone()
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
            .unwrap_or(DEFAULT_FILE),
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

/// Default vault name: the directory name, plus the file's prefix unless it
/// is the default `secrets` (`my-project`, `my-project/prod`).
pub fn default_name(path: &Path) -> String {
    let dir = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("agentpass");
    let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match file.strip_suffix(SUFFIX) {
        Some(prefix) if !prefix.is_empty() && prefix != "secrets" => format!("{dir}/{prefix}"),
        _ => dir.to_owned(),
    }
}

/// Validates a vault name given by the user.
pub fn validate_vault_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        bail!("invalid vault name {name:?}: use 1 to 64 printable characters");
    }
    Ok(name.to_owned())
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

/// `prod` → `prod.agentpass.toml`; paths ending in `.toml` are kept.
fn with_suffix(p: &Path) -> PathBuf {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.ends_with(".toml") {
        p.to_owned()
    } else {
        p.with_file_name(format!("{name}{SUFFIX}"))
    }
}

/// Several vaults in one directory: the user has to pick one with `--file`.
#[derive(Debug, thiserror::Error)]
#[error(
    "found {} vaults in {}: {}. Choose one with --file <path>, e.g. `agentpass --file {} …`",
    .files.len(),
    .dir.display(),
    .files.join(", "),
    .files[0]
)]
pub struct AmbiguousVault {
    pub dir: PathBuf,
    pub files: Vec<String>,
}

/// The vault in `dir`: its only `*.agentpass.toml` (or a legacy
/// `agentpass.toml`). Several vaults are an error, never a guess.
pub fn find_in_dir(dir: &Path) -> Result<Option<PathBuf>> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("listing {}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(SUFFIX) && n.len() > SUFFIX.len())
        })
        .collect();
    found.sort();
    match found.len() {
        0 => {
            let legacy = dir.join(LEGACY_FILE);
            Ok(legacy.is_file().then_some(legacy))
        }
        1 => Ok(found.pop()),
        _ => Err(AmbiguousVault {
            dir: dir.to_owned(),
            files: found
                .iter()
                .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
                .collect(),
        }
        .into()),
    }
}

/// Finds the vault.
///
/// * `--file` (or `AGENTPASS_FILE`): a path (relative to the current
///   directory), a directory containing exactly one vault, or a bare name
///   (`prod` → `prod.agentpass.toml`).
/// * Otherwise the `*.agentpass.toml` in the current directory, or in the
///   nearest parent that has one. More than one in that directory is an error
///   listing them.
pub fn locate(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if p.is_dir() {
            return match find_in_dir(p)? {
                Some(f) => absolute(&f),
                None => bail!("no *{SUFFIX} vault in {}", p.display()),
            };
        }
        let p = if p.is_file() {
            p.to_owned()
        } else {
            with_suffix(p)
        };
        if !p.is_file() {
            bail!("vault file {} does not exist", p.display());
        }
        return absolute(&p);
    }
    let cwd = std::env::current_dir()?;
    for dir in cwd.ancestors() {
        if let Some(f) = find_in_dir(dir)? {
            return absolute(&f);
        }
    }
    bail!(
        "no *{SUFFIX} vault found in {} or its parents; run `agentpass setup` or pass --file",
        cwd.display()
    )
}

/// Path for a new vault: `./secrets.agentpass.toml`, a directory (gets
/// `secrets.agentpass.toml`), a name (`prod` → `prod.agentpass.toml`) or a
/// full `<name>.agentpass.toml` path.
pub fn new_vault_path(explicit: Option<&Path>) -> Result<PathBuf> {
    let p = match explicit {
        None => PathBuf::from(DEFAULT_FILE),
        Some(p) if p.is_dir() => p.join(DEFAULT_FILE),
        Some(p) => with_suffix(p),
    };
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !name.ends_with(SUFFIX) || name.len() == SUFFIX.len() {
        bail!("vault files must be named <name>{SUFFIX} (got {name:?})");
    }
    absolute(&p)
}

/// Secret names: `/`-separated segments (folders), e.g. `production/DB_PASSWORD`.
/// Each segment uses letters, digits, `_`, `.` and `-` and must not start
/// with `.` or `-`.
pub fn validate_key_name(key: &str) -> Result<()> {
    let segment_ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            && !s.starts_with(['.', '-'])
    };
    if key.len() <= 128 && key.split('/').all(segment_ok) {
        Ok(())
    } else {
        bail!(
            "invalid secret name {key:?}: use letters, digits, '_', '.', '-', and '/' for folders \
             (e.g. production/DB_PASSWORD; max 128 chars)"
        )
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
            name: "test".into(),
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
        let path = dir.join(DEFAULT_FILE);
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
    fn several_vaults_in_one_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (v, _) = new_vault(dir.path());
        let prod = dir.path().join("prod.agentpass.toml");
        std::fs::copy(&v.path, &prod).unwrap();
        // Several vaults: never guess, list them.
        let err = locate(Some(dir.path())).unwrap_err();
        let amb = err
            .downcast_ref::<AmbiguousVault>()
            .expect("ambiguous error");
        assert_eq!(
            amb.files,
            vec!["prod.agentpass.toml", "secrets.agentpass.toml"]
        );
        assert!(err.to_string().contains("--file"));
        // A bare name selects <name>.agentpass.toml.
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let by_name = locate(Some(Path::new("prod")));
        std::env::set_current_dir(prev).unwrap();
        assert_eq!(by_name.unwrap(), absolute(&prod).unwrap());
        std::fs::remove_file(&v.path).unwrap();
        let other = dir.path().join("dev.agentpass.toml");
        std::fs::copy(&prod, &other).unwrap();
        assert!(
            locate(Some(dir.path())).is_err(),
            "ambiguous without a default"
        );
    }

    #[test]
    fn names_and_new_paths() {
        assert_eq!(
            default_name(Path::new("/x/proj/secrets.agentpass.toml")),
            "proj"
        );
        assert_eq!(
            default_name(Path::new("/x/proj/prod.agentpass.toml")),
            "proj/prod"
        );
        let dir = tempfile::tempdir().unwrap();
        let base = absolute(dir.path()).unwrap();
        assert_eq!(
            new_vault_path(Some(dir.path())).unwrap(),
            base.join(DEFAULT_FILE)
        );
        assert_eq!(
            new_vault_path(Some(&dir.path().join("prod"))).unwrap(),
            base.join("prod.agentpass.toml")
        );
        assert!(new_vault_path(Some(&dir.path().join("x.toml"))).is_err());
        assert!(new_vault_path(Some(&dir.path().join(".agentpass.toml"))).is_err());
        assert!(validate_vault_name("  my vault ").unwrap() == "my vault");
        assert!(validate_vault_name("").is_err());
    }

    #[test]
    fn legacy_files_without_name_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let (v, _) = new_vault(dir.path());
        let legacy = dir.path().join("agentpass.toml");
        let text = std::fs::read_to_string(&v.path)
            .unwrap()
            .replace("name = \"test\"\n", "");
        std::fs::write(&legacy, text).unwrap();
        std::fs::remove_file(&v.path).unwrap();
        let found = locate(Some(dir.path())).unwrap();
        assert_eq!(found, absolute(&legacy).unwrap());
        let loaded = Vault::load(&found).unwrap();
        assert!(!loaded.name().is_empty());
    }

    #[test]
    fn key_names() {
        for ok in [
            "A",
            "GITHUB_TOKEN",
            "db.password",
            "x-1",
            "production/DB",
            "a/b/c",
        ] {
            validate_key_name(ok).unwrap();
        }
        for bad in [
            "",
            ".a",
            "-a",
            "a b",
            "a=b",
            "ä",
            "/a",
            "a/",
            "a//b",
            "a/.b",
            &"x".repeat(129),
        ] {
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
