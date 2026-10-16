//! Bindings to `js/webauthn.js` (navigator.credentials + PRF extension).

use agentpass_protocol::RegisterInfo;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/js/webauthn.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = registerPasskey)]
    async fn register_passkey(opts: String) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = evaluatePrf)]
    async fn evaluate_prf(opts: String) -> Result<JsValue, JsValue>;
}

#[derive(Deserialize)]
pub struct PrfResult {
    pub credential_id: String,
    pub prf_output: String,
}

fn explain(err: JsValue) -> String {
    let msg = err
        .dyn_ref::<js_sys::Error>()
        .map(|e| String::from(e.message()))
        .or_else(|| err.as_string())
        .unwrap_or_else(|| "unknown error".into());
    if msg.contains("PRF_UNSUPPORTED") {
        "This passkey does not support the PRF extension, which agentpass needs to derive the vault key. \
         Try a FIDO2 security key, a recent Chrome/Safari/Firefox, or a password manager with PRF support \
         (e.g. 1Password, Bitwarden, iCloud Keychain, Google Password Manager)."
            .into()
    } else if msg.contains("UNSUPPORTED_BROWSER") {
        "This browser does not support passkeys on this page. Open the link at http://localhost in a current browser.".into()
    } else if msg.starts_with("NotAllowedError") {
        "The passkey prompt was cancelled or timed out. Try again.".into()
    } else if msg.starts_with("InvalidStateError") {
        "This passkey is already registered for this vault. Use a different one.".into()
    } else if msg.starts_with("SecurityError") {
        "The browser rejected the request. Make sure the address starts with http://localhost."
            .into()
    } else {
        msg
    }
}

fn parse(v: JsValue) -> Result<PrfResult, String> {
    let s = v.as_string().ok_or("unexpected WebAuthn result")?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

pub async fn register(info: &RegisterInfo) -> Result<PrfResult, String> {
    let opts = serde_json::to_string(info).map_err(|e| e.to_string())?;
    parse(register_passkey(opts).await.map_err(explain)?)
}

/// Passkey assertion with PRF; `info` needs `rp_id`, `challenge` and
/// `passkeys` (UnlockInfo or EditInfo).
pub async fn evaluate(info: &impl serde::Serialize) -> Result<PrfResult, String> {
    let opts = serde_json::to_string(info).map_err(|e| e.to_string())?;
    parse(evaluate_prf(opts).await.map_err(explain)?)
}
