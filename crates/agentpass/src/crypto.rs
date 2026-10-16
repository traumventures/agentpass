//! Vault cryptography.
//!
//! * Every vault has an X25519 key pair. The public key lives in the vault
//!   file, so values can be added while the vault is locked.
//! * Values are sealed to the public key (ECIES: ephemeral X25519,
//!   HKDF-SHA256, ChaCha20-Poly1305). The vault id and the secret's key name
//!   are authenticated, so ciphertexts cannot be moved between keys/vaults.
//! * The private key is wrapped once per passkey with a key derived (HKDF)
//!   from that passkey's WebAuthn PRF output (XChaCha20-Poly1305).
//!
//! Decrypted material only ever lives in [`SecureBuf`]s.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::secmem::SecureBuf;

pub const KEY_LEN: usize = 32;
pub const PRF_LEN: usize = 32;
const TAG_LEN: usize = 16;
const VALUE_PREFIX: &str = "ap1:";
const WRAP_PREFIX: &str = "apw1:";
/// Upper bound for a single secret value.
pub const MAX_VALUE_LEN: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("malformed ciphertext")]
    Malformed,
    #[error("decryption failed (wrong key, or the ciphertext was modified or moved)")]
    Decrypt,
    #[error("secret value is too large (max {MAX_VALUE_LEN} bytes)")]
    TooLarge,
    #[error("secure memory: {0}")]
    Memory(#[from] std::io::Error),
    #[error("random number generator failed: {0}")]
    Random(String),
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(out)
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn from_b64url(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn from_b64(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}

/// A vault private key, held in locked memory.
pub struct PrivateKey(SecureBuf);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateKey([REDACTED])")
    }
}

impl PrivateKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut buf = SecureBuf::new(KEY_LEN)?;
        getrandom::getrandom(buf.as_mut_slice()).map_err(|e| CryptoError::Random(e.to_string()))?;
        Ok(Self(buf))
    }

    fn scalar(&self) -> Zeroizing<[u8; KEY_LEN]> {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        k.copy_from_slice(self.0.as_slice());
        k
    }

    pub fn public_key(&self) -> [u8; KEY_LEN] {
        x25519_dalek::x25519(*self.scalar(), x25519_dalek::X25519_BASEPOINT_BYTES)
    }

    fn diffie_hellman(&self, public: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(x25519_dalek::x25519(*self.scalar(), *public))
    }

    /// Raw key bytes. Only for tests that check memory scrubbing.
    #[doc(hidden)]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn addr(&self) -> usize {
        self.0.addr()
    }
}

fn value_aad(vault_id: &str, key_name: &str) -> Vec<u8> {
    let mut aad = b"agentpass v1 value\0".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(key_name.as_bytes());
    aad
}

fn value_cipher(
    shared: &[u8; KEY_LEN],
    eph_pub: &[u8; KEY_LEN],
    recipient: &[u8; KEY_LEN],
) -> Result<ChaCha20Poly1305, CryptoError> {
    if shared.iter().all(|&b| b == 0) {
        // Low-order point.
        return Err(CryptoError::Malformed);
    }
    let mut salt = [0u8; 2 * KEY_LEN];
    salt[..KEY_LEN].copy_from_slice(eph_pub);
    salt[KEY_LEN..].copy_from_slice(recipient);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"agentpass v1 value key", key.as_mut())
        .expect("valid HKDF length");
    Ok(ChaCha20Poly1305::new(key.as_ref().into()))
}

/// Encrypts a value to the vault's public key.
pub fn seal_value(
    public: &[u8; KEY_LEN],
    vault_id: &str,
    key_name: &str,
    plaintext: &[u8],
) -> Result<String, CryptoError> {
    if plaintext.len() > MAX_VALUE_LEN {
        return Err(CryptoError::TooLarge);
    }
    let eph = Zeroizing::new(random_bytes::<KEY_LEN>()?);
    let eph_pub = x25519_dalek::x25519(*eph, x25519_dalek::X25519_BASEPOINT_BYTES);
    let shared = Zeroizing::new(x25519_dalek::x25519(*eph, *public));
    let cipher = value_cipher(&shared, &eph_pub, public)?;
    // Each value uses a fresh ephemeral key, so a fixed nonce is safe.
    let nonce = Default::default();
    let mut buf = Zeroizing::new(Vec::with_capacity(KEY_LEN + plaintext.len() + TAG_LEN));
    buf.extend_from_slice(&eph_pub);
    buf.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, &value_aad(vault_id, key_name), &mut buf[KEY_LEN..])
        .map_err(|_| CryptoError::Malformed)?;
    buf.extend_from_slice(&tag);
    Ok(format!("{VALUE_PREFIX}{}", b64(&buf)))
}

/// Decrypts a sealed value straight into locked memory.
pub fn open_value(
    key: &PrivateKey,
    public: &[u8; KEY_LEN],
    vault_id: &str,
    key_name: &str,
    sealed: &str,
) -> Result<SecureBuf, CryptoError> {
    let raw = sealed
        .strip_prefix(VALUE_PREFIX)
        .and_then(from_b64)
        .ok_or(CryptoError::Malformed)?;
    if raw.len() < KEY_LEN + TAG_LEN {
        return Err(CryptoError::Malformed);
    }
    let eph_pub: [u8; KEY_LEN] = raw[..KEY_LEN].try_into().unwrap();
    let (ct, tag) = raw[KEY_LEN..].split_at(raw.len() - KEY_LEN - TAG_LEN);
    let shared = key.diffie_hellman(&eph_pub);
    let cipher = value_cipher(&shared, &eph_pub, public)?;
    let mut out = SecureBuf::from_slice(ct)?;
    cipher
        .decrypt_in_place_detached(
            &Default::default(),
            &value_aad(vault_id, key_name),
            out.as_mut_slice(),
            Tag::from_slice(tag),
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(out)
}

fn wrap_aad(vault_id: &str, credential_id: &str) -> Vec<u8> {
    let mut aad = b"agentpass v1 wrap\0".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(credential_id.as_bytes());
    aad
}

fn wrap_cipher(prf_output: &[u8], vault_id: &str, credential_id: &str) -> XChaCha20Poly1305 {
    let hk = Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), prf_output);
    let mut info = b"agentpass v1 wrap key\0".to_vec();
    info.extend_from_slice(credential_id.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut()).expect("valid HKDF length");
    XChaCha20Poly1305::new(key.as_ref().into())
}

/// Wraps the private key with a passkey's PRF output.
pub fn wrap_private_key(
    key: &PrivateKey,
    prf_output: &[u8],
    vault_id: &str,
    credential_id: &str,
) -> Result<String, CryptoError> {
    let cipher = wrap_cipher(prf_output, vault_id, credential_id);
    let nonce = random_bytes::<24>()?;
    let mut buf = Zeroizing::new(Vec::with_capacity(24 + KEY_LEN + TAG_LEN));
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(key.0.as_slice());
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &wrap_aad(vault_id, credential_id),
            &mut buf[24..],
        )
        .map_err(|_| CryptoError::Malformed)?;
    buf.extend_from_slice(&tag);
    Ok(format!("{WRAP_PREFIX}{}", b64(&buf)))
}

/// Unwraps the private key with a passkey's PRF output and checks it against
/// the vault's public key.
pub fn unwrap_private_key(
    wrapped: &str,
    prf_output: &[u8],
    vault_id: &str,
    credential_id: &str,
    public: &[u8; KEY_LEN],
) -> Result<PrivateKey, CryptoError> {
    let raw = wrapped
        .strip_prefix(WRAP_PREFIX)
        .and_then(from_b64)
        .ok_or(CryptoError::Malformed)?;
    if raw.len() != 24 + KEY_LEN + TAG_LEN {
        return Err(CryptoError::Malformed);
    }
    let cipher = wrap_cipher(prf_output, vault_id, credential_id);
    let mut out = SecureBuf::from_slice(&raw[24..24 + KEY_LEN])?;
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&raw[..24]),
            &wrap_aad(vault_id, credential_id),
            out.as_mut_slice(),
            Tag::from_slice(&raw[24 + KEY_LEN..]),
        )
        .map_err(|_| CryptoError::Decrypt)?;
    let key = PrivateKey(out);
    if &key.public_key() != public {
        return Err(CryptoError::Decrypt);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (PrivateKey, [u8; 32]) {
        let k = PrivateKey::generate().unwrap();
        let p = k.public_key();
        (k, p)
    }

    #[test]
    fn value_roundtrip() {
        let (k, p) = setup();
        for msg in [&b""[..], b"x", b"hunter2", &[0u8; 5000][..]] {
            let s = seal_value(&p, "vault", "KEY", msg).unwrap();
            assert!(s.starts_with("ap1:"));
            let out = open_value(&k, &p, "vault", "KEY", &s).unwrap();
            assert_eq!(out.as_slice(), msg);
        }
    }

    #[test]
    fn sealing_is_randomised() {
        let (_, p) = setup();
        let a = seal_value(&p, "v", "K", b"same").unwrap();
        let b = seal_value(&p, "v", "K", b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn value_is_bound_to_key_name_and_vault() {
        let (k, p) = setup();
        let s = seal_value(&p, "vault", "A", b"secret").unwrap();
        assert!(matches!(
            open_value(&k, &p, "vault", "B", &s),
            Err(CryptoError::Decrypt)
        ));
        assert!(matches!(
            open_value(&k, &p, "other", "A", &s),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn wrong_private_key_fails() {
        let (_, p) = setup();
        let (k2, _) = setup();
        let s = seal_value(&p, "v", "K", b"secret").unwrap();
        assert!(open_value(&k2, &p, "v", "K", &s).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let (k, p) = setup();
        let s = seal_value(&p, "v", "K", b"secret").unwrap();
        let mut raw = from_b64(&s[4..]).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let t = format!("ap1:{}", b64(&raw));
        assert!(open_value(&k, &p, "v", "K", &t).is_err());
        assert!(matches!(
            open_value(&k, &p, "v", "K", "ap1:!!"),
            Err(CryptoError::Malformed)
        ));
        assert!(matches!(
            open_value(&k, &p, "v", "K", "nope"),
            Err(CryptoError::Malformed)
        ));
    }

    #[test]
    fn too_large_values_are_rejected() {
        let (_, p) = setup();
        let big = vec![0u8; MAX_VALUE_LEN + 1];
        assert!(matches!(
            seal_value(&p, "v", "K", &big),
            Err(CryptoError::TooLarge)
        ));
    }

    #[test]
    fn wrap_roundtrip_and_binding() {
        let (k, p) = setup();
        let prf = [9u8; 32];
        let w = wrap_private_key(&k, &prf, "vault", "cred").unwrap();
        let k2 = unwrap_private_key(&w, &prf, "vault", "cred", &p).unwrap();
        assert_eq!(k2.expose(), k.expose());
        assert!(unwrap_private_key(&w, &[8u8; 32], "vault", "cred", &p).is_err());
        assert!(unwrap_private_key(&w, &prf, "vault", "other", &p).is_err());
        assert!(unwrap_private_key(&w, &prf, "other", "cred", &p).is_err());
        let (_, wrong_pub) = setup();
        assert!(unwrap_private_key(&w, &prf, "vault", "cred", &wrong_pub).is_err());
    }

    #[test]
    fn property_random_values_roundtrip() {
        let (k, p) = setup();
        for i in 0..200usize {
            let len = (random_bytes::<2>().unwrap()[0] as usize) * (i % 7 + 1);
            let mut msg = vec![0u8; len];
            getrandom::getrandom(&mut msg).unwrap();
            let name = format!("K{i}");
            let s = seal_value(&p, "v", &name, &msg).unwrap();
            assert_eq!(
                open_value(&k, &p, "v", &name, &s).unwrap().as_slice(),
                &msg[..]
            );
        }
    }
}
