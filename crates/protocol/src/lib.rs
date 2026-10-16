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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    fn flow_info_is_tagged_by_kind() {
        let info = FlowInfo::Unlock(UnlockInfo {
            vault: VaultSummary {
                name: "v".into(),
                path: "/v/agentpass.toml".into(),
                vault_id: "id".into(),
                secret_count: 2,
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
