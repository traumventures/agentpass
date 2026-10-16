//! JSON types exchanged between the agentpass daemon's localhost web server
//! and the Yew web UI.
//!
//! Binary values are encoded as unpadded base64url strings.

use serde::{Deserialize, Serialize};

/// Header carrying the one-time flow token taken from the URL fragment.
pub const TOKEN_HEADER: &str = "x-agentpass-token";

/// Relying party id used for every passkey.
pub const RP_ID: &str = "localhost";

/// Description of the pending browser flow, returned by `GET /api/flow`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowInfo {
    /// Create a new vault by registering its first passkey.
    Setup(RegisterInfo),
    /// Add another passkey to an unlocked vault.
    Enroll(RegisterInfo),
    /// Unlock a vault with one of its passkeys.
    Unlock(UnlockInfo),
    /// Open the secrets editor (after a passkey check).
    Edit(EditInfo),
    /// The agent asks the user to provide one secret.
    Request(RequestInfo),
}

/// Parameters for opening the editor: a passkey assertion (PRF) proves the
/// user and yields the key needed to re-encrypt renamed secrets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditInfo {
    pub vault: VaultSummary,
    pub rp_id: String,
    pub challenge: String,
    pub passkeys: Vec<PasskeyDescriptor>,
}

/// A secret the agent wants the user to provide. Every field is a
/// suggestion the user can change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestInfo {
    pub vault: VaultSummary,
    /// Suggested full key, e.g. `production/STRIPE_KEY`.
    pub key: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Why the agent needs it.
    #[serde(default)]
    pub reason: Option<String>,
}

/// One change made in the editor. Folders are key prefixes, so folder
/// operations are expressed as operations on the keys inside them.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum EditOp {
    /// Create or update a secret. `value: None` keeps the stored value
    /// (only valid for existing secrets).
    Put {
        key: String,
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        description: Option<String>,
    },
    Delete {
        key: String,
    },
    /// Rename a secret (re-encrypts it under the new name).
    Rename {
        from: String,
        to: String,
    },
}

impl std::fmt::Debug for EditOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EditOp::Put { key, value, .. } => write!(
                f,
                "Put({key}, value: {})",
                if value.is_some() {
                    "[REDACTED]"
                } else {
                    "unchanged"
                }
            ),
            EditOp::Delete { key } => write!(f, "Delete({key})"),
            EditOp::Rename { from, to } => write!(f, "Rename({from} -> {to})"),
        }
    }
}

/// Body of `POST /api/edit`. Applied atomically: all or nothing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditRequest {
    pub ops: Vec<EditOp>,
}

/// Response of `POST /api/edit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditResult {
    pub message: String,
    pub vault: VaultSummary,
}

/// Parameters for registering a passkey with the PRF extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterInfo {
    pub vault: VaultSummary,
    pub rp_id: String,
    /// WebAuthn user handle (base64url).
    pub user_id: String,
    pub user_name: String,
    /// Random challenge (base64url).
    pub challenge: String,
    /// PRF salt for the new passkey (base64url).
    pub prf_salt: String,
    /// Credential ids already enrolled, to be excluded (base64url).
    pub exclude_credentials: Vec<String>,
    /// Default label proposed for the new passkey.
    pub suggested_label: String,
}

/// Parameters for unlocking a vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnlockInfo {
    pub vault: VaultSummary,
    pub rp_id: String,
    /// Random challenge (base64url).
    pub challenge: String,
    pub passkeys: Vec<PasskeyDescriptor>,
    /// Unlock duration suggested by the agent, in seconds. `None` means no
    /// suggestion was made.
    pub suggested_duration_secs: Option<u64>,
    /// Upper bound for custom durations, in seconds.
    pub max_duration_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultSummary {
    pub name: String,
    pub path: String,
    pub vault_id: String,
    pub secret_count: usize,
    /// Every secret (names and descriptions only, never values), sorted by
    /// key. `/` in a key separates folders.
    #[serde(default)]
    pub secrets: Vec<SecretSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretSummary {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasskeyDescriptor {
    pub label: String,
    /// Credential id (base64url).
    pub credential_id: String,
    /// PRF salt (base64url).
    pub prf_salt: String,
}

/// Body of `POST /api/flow/complete`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowCompletion {
    /// A passkey was registered (setup or enroll).
    Registered {
        credential_id: String,
        prf_output: String,
        label: String,
    },
    /// A passkey produced a PRF output for unlocking.
    Unlocked {
        credential_id: String,
        prf_output: String,
        /// How long the vault stays unlocked. `None` means until it is
        /// locked explicitly (or the daemon stops, the user logs out or the
        /// machine sleeps).
        duration_secs: Option<u64>,
    },
    /// Passkey check that opens the editor.
    EditAuth {
        credential_id: String,
        prf_output: String,
    },
    /// The user provided the requested secret (possibly under another name).
    Provided {
        key: String,
        #[serde(default)]
        description: Option<String>,
        value: String,
        /// Allow replacing an existing secret with this name.
        #[serde(default)]
        replace: bool,
    },
    /// The user declined the request.
    Declined,
    /// The user closed the editor.
    EditClosed,
}

impl std::fmt::Debug for FlowCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print PRF outputs or secret values.
        let kind = match self {
            FlowCompletion::Registered { .. } => "Registered",
            FlowCompletion::Unlocked { .. } => "Unlocked",
            FlowCompletion::EditAuth { .. } => "EditAuth",
            FlowCompletion::Provided { .. } => "Provided",
            FlowCompletion::Declined => "Declined",
            FlowCompletion::EditClosed => "EditClosed",
        };
        write!(f, "FlowCompletion::{kind}([REDACTED])")
    }
}

/// Response of `POST /api/flow/complete`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowResult {
    pub message: String,
}

/// Error body returned by every API endpoint on failure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_is_tagged_by_kind() {
        let c = FlowCompletion::Unlocked {
            credential_id: "abc".into(),
            prf_output: "def".into(),
            duration_secs: None,
        };
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["kind"], "unlocked");
        assert_eq!(json["duration_secs"], serde_json::Value::Null);
        let back: FlowCompletion = serde_json::from_value(json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn secret_values_are_never_debug_printed() {
        let p = FlowCompletion::Provided {
            key: "K".into(),
            description: None,
            value: "hunter2".into(),
            replace: false,
        };
        assert!(!format!("{p:?}").contains("hunter2"));
        let op = EditOp::Put {
            key: "K".into(),
            value: Some("hunter2".into()),
            description: None,
        };
        assert!(!format!("{op:?}").contains("hunter2"));
    }

    #[test]
    fn flow_info_is_tagged_by_kind() {
        let info = FlowInfo::Unlock(UnlockInfo {
            vault: VaultSummary {
                name: "v".into(),
                path: "/v/agentpass.toml".into(),
                vault_id: "id".into(),
                secret_count: 2,
                secrets: vec![],
            },
            rp_id: RP_ID.into(),
            challenge: "c".into(),
            passkeys: vec![],
            suggested_duration_secs: Some(3600),
            max_duration_secs: 7 * 86400,
        });
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["kind"], "unlock");
        assert_eq!(json["vault"]["secret_count"], 2);
    }
}
