//! Applying editor changes to a vault, all or nothing.
//!
//! Ops are applied in three phases regardless of their order: deletes, then
//! renames (all sources are taken out before any target is written, so
//! swaps and folder moves work), then puts. Renames re-encrypt the value
//! under its new name because the name is authenticated with the value.

use std::collections::{BTreeMap, HashSet};

use zeroize::Zeroize;

use super::Fail;
use crate::crypto::{self, PrivateKey};
use crate::vault::{self, SecretEntry, Vault};
use agentpass_protocol::EditOp;

fn invalid(msg: String) -> Fail {
    Fail::invalid(msg)
}

fn check_name(key: &str) -> Result<(), Fail> {
    vault::validate_key_name(key).map_err(|e| invalid(e.to_string()))
}

fn clean_description(d: String) -> Option<String> {
    let d: String = d.chars().filter(|c| !c.is_control()).take(200).collect();
    let d = d.trim();
    (!d.is_empty()).then(|| d.to_owned())
}

/// Applies `ops` to `v.file` (not saved). Returns the number of ops.
pub fn apply(v: &mut Vault, key: &PrivateKey, mut ops: Vec<EditOp>) -> Result<usize, Fail> {
    let result = apply_inner(v, key, &ops);
    for op in &mut ops {
        if let EditOp::Put {
            value: Some(value), ..
        } = op
        {
            value.zeroize();
        }
    }
    result
}

fn apply_inner(v: &mut Vault, key: &PrivateKey, ops: &[EditOp]) -> Result<usize, Fail> {
    if ops.is_empty() {
        return Err(invalid("nothing to save".into()));
    }
    let public = v.public_key()?;
    let id = v.id().to_owned();
    let mut work: BTreeMap<String, SecretEntry> = v.file.secrets.clone();

    for op in ops {
        if let EditOp::Delete { key: k } = op {
            work.remove(k)
                .ok_or_else(|| invalid(format!("cannot delete {k}: no such secret")))?;
        }
    }

    let mut moved = Vec::new();
    let mut sources = HashSet::new();
    for op in ops {
        if let EditOp::Rename { from, to } = op {
            check_name(to)?;
            if !sources.insert(from.clone()) {
                return Err(invalid(format!("{from} is renamed twice")));
            }
            let entry = work
                .remove(from)
                .ok_or_else(|| invalid(format!("cannot rename {from}: no such secret")))?;
            let plain = crypto::open_value(key, &public, &id, from, &entry.value)
                .map_err(|e| Fail::internal(format!("{from}: {e}")))?;
            moved.push((to.clone(), entry.description, plain));
        }
    }
    for (to, description, plain) in moved {
        if work.contains_key(&to) {
            return Err(invalid(format!("cannot rename to {to}: it already exists")));
        }
        let value = crypto::seal_value(&public, &id, &to, plain.as_slice())?;
        work.insert(to, SecretEntry { description, value });
    }

    for op in ops {
        if let EditOp::Put {
            key: k,
            value,
            description,
        } = op
        {
            check_name(k)?;
            let description = match description {
                Some(d) => clean_description(d.clone()),
                None => work.get(k).and_then(|e| e.description.clone()),
            };
            let value = match value {
                Some(val) if val.is_empty() => {
                    return Err(invalid(format!("{k}: the value is empty")))
                }
                Some(val) => crypto::seal_value(&public, &id, k, val.as_bytes())?,
                None => work
                    .get(k)
                    .map(|e| e.value.clone())
                    .ok_or_else(|| invalid(format!("{k}: a new secret needs a value")))?,
            };
            work.insert(k.clone(), SecretEntry { description, value });
        }
    }

    v.file.secrets = work;
    Ok(ops.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{VaultFile, VERSION};

    fn vault() -> (tempfile::TempDir, Vault, PrivateKey) {
        let dir = tempfile::tempdir().unwrap();
        let key = PrivateKey::generate().unwrap();
        let file = VaultFile {
            version: VERSION,
            vault_id: "V".into(),
            name: "t".into(),
            public_key: crypto::b64(&key.public_key()),
            passkeys: vec![],
            secrets: Default::default(),
        };
        let path = dir.path().join("secrets.agentpass.toml");
        vault::write_atomic(&path, &file).unwrap();
        let mut v = Vault::load(&path).unwrap();
        for (k, val) in [
            ("A", "a"),
            ("prod/DB", "p"),
            ("prod/aws/K", "k"),
            ("test/DB", "t"),
        ] {
            v.set_secret(k, val.as_bytes(), Some(format!("desc {k}")))
                .unwrap();
        }
        (dir, v, key)
    }

    fn get(v: &Vault, key: &PrivateKey, k: &str) -> String {
        let e = &v.file.secrets[k];
        let p = crypto::open_value(key, &v.public_key().unwrap(), v.id(), k, &e.value).unwrap();
        String::from_utf8(p.as_slice().to_vec()).unwrap()
    }

    fn put(k: &str, val: Option<&str>, d: Option<&str>) -> EditOp {
        EditOp::Put {
            key: k.into(),
            value: val.map(Into::into),
            description: d.map(Into::into),
        }
    }

    #[test]
    fn rename_folder_moves_and_reencrypts() {
        let (_d, mut v, key) = vault();
        let ops = vec![
            EditOp::Rename {
                from: "prod/DB".into(),
                to: "production/DB".into(),
            },
            EditOp::Rename {
                from: "prod/aws/K".into(),
                to: "production/aws/K".into(),
            },
        ];
        assert_eq!(apply(&mut v, &key, ops).unwrap(), 2);
        assert_eq!(get(&v, &key, "production/DB"), "p");
        assert_eq!(get(&v, &key, "production/aws/K"), "k");
        assert_eq!(
            v.file.secrets["production/DB"].description.as_deref(),
            Some("desc prod/DB")
        );
        assert!(!v.file.secrets.contains_key("prod/DB"));
    }

    #[test]
    fn swap_works_and_conflicts_fail_atomically() {
        let (_d, mut v, key) = vault();
        let swap = vec![
            EditOp::Rename {
                from: "prod/DB".into(),
                to: "test/DB".into(),
            },
            EditOp::Rename {
                from: "test/DB".into(),
                to: "prod/DB".into(),
            },
        ];
        apply(&mut v, &key, swap).unwrap();
        assert_eq!(get(&v, &key, "prod/DB"), "t");
        assert_eq!(get(&v, &key, "test/DB"), "p");

        let before = v.file.secrets.clone();
        let bad = vec![
            EditOp::Delete { key: "A".into() },
            EditOp::Rename {
                from: "prod/DB".into(),
                to: "test/DB".into(),
            },
        ];
        assert!(apply(&mut v, &key, bad).is_err());
        assert_eq!(v.file.secrets, before, "nothing applied on error");
    }

    #[test]
    fn put_add_override_describe_and_delete_folder() {
        let (_d, mut v, key) = vault();
        let ops = vec![
            put("new/X", Some("x"), Some("new one")),
            put("A", Some("a2"), None),
            put("test/DB", None, Some("")),
            EditOp::Delete {
                key: "prod/DB".into(),
            },
            EditOp::Delete {
                key: "prod/aws/K".into(),
            },
        ];
        apply(&mut v, &key, ops).unwrap();
        assert_eq!(get(&v, &key, "new/X"), "x");
        assert_eq!(get(&v, &key, "A"), "a2");
        assert_eq!(v.file.secrets["A"].description.as_deref(), Some("desc A"));
        assert_eq!(v.file.secrets["test/DB"].description, None);
        assert_eq!(get(&v, &key, "test/DB"), "t");
        assert!(v.file.secrets.keys().all(|k| !k.starts_with("prod/")));
    }

    #[test]
    fn invalid_ops_are_rejected() {
        let (_d, mut v, key) = vault();
        assert!(apply(&mut v, &key, vec![]).is_err());
        assert!(apply(&mut v, &key, vec![put("NEW", None, None)]).is_err());
        assert!(apply(&mut v, &key, vec![put("bad//x", Some("v"), None)]).is_err());
        assert!(apply(&mut v, &key, vec![put("A", Some(""), None)]).is_err());
        assert!(apply(&mut v, &key, vec![EditOp::Delete { key: "NOPE".into() }]).is_err());
        let wrong = PrivateKey::generate().unwrap();
        let r = vec![EditOp::Rename {
            from: "A".into(),
            to: "B".into(),
        }];
        assert!(apply(&mut v, &wrong, r).is_err());
    }
}
