//! The background daemon. It holds unlocked vault keys in locked memory,
//! answers CLI requests over a Unix socket and serves the passkey web UI on
//! `127.0.0.1`.

#[cfg(target_os = "macos")]
mod macos;
mod watch;
mod web;

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

use crate::crypto::{self, PrivateKey, KEY_LEN, PRF_LEN};
use crate::ipc::{self, ErrorCode, FlowState, Request, Response, VaultStatus};
use crate::secmem::{self, SecureBuf};
use crate::vault::{self, PasskeyEntry, Vault, VaultFile};
use agentpass_protocol as proto;

pub const DEFAULT_PORT: u16 = 47117;
/// Longest custom unlock duration the web UI accepts.
pub const MAX_DURATION: Duration = Duration::from_secs(30 * 24 * 3600);
const FLOW_TTL: Duration = Duration::from_secs(15 * 60);
const FLOW_MAX_ATTEMPTS: u32 = 5;
const RESULT_TTL: Duration = Duration::from_secs(3600);
const DEFAULT_IDLE_EXIT: Duration = Duration::from_secs(30 * 60);

macro_rules! log {
    ($($arg:tt)*) => {
        eprintln!("{} agentpass[{}]: {}", humantime::format_rfc3339_seconds(std::time::SystemTime::now()), std::process::id(), format!($($arg)*))
    };
}
pub(crate) use log;

struct Unlocked {
    key: PrivateKey,
    public: [u8; KEY_LEN],
    path: PathBuf,
    name: String,
    unlocked_at: SystemTime,
    expires: Option<Instant>,
}

enum FlowKind {
    Setup {
        name: String,
        label: String,
        user_id: [u8; 16],
        prf_salt: [u8; 32],
    },
    Enroll {
        vault_id: String,
        label: String,
        user_id: [u8; 16],
        prf_salt: [u8; 32],
    },
    Unlock {
        vault_id: String,
        suggest_secs: Option<u64>,
    },
}

struct Flow {
    id: String,
    vault_path: PathBuf,
    created: Instant,
    attempts: u32,
    challenge: [u8; 32],
    kind: FlowKind,
}

#[derive(Default)]
struct State {
    unlocked: HashMap<String, Unlocked>,
    /// Pending browser flows by secret token.
    flows: HashMap<String, Flow>,
    /// Finished flows by flow id.
    results: HashMap<String, (FlowState, Instant)>,
}

pub struct Daemon {
    state: Mutex<State>,
    port: u16,
    last_activity: Mutex<Instant>,
    shutdown: tokio::sync::Notify,
}

/// Error surfaced to the CLI or the web UI.
#[derive(Debug)]
pub struct Fail {
    pub code: ErrorCode,
    pub message: String,
}

impl Fail {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Invalid, message)
    }
    fn internal(err: impl std::fmt::Display) -> Self {
        Self::new(ErrorCode::Internal, format!("{err:#}"))
    }
}

impl From<anyhow::Error> for Fail {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(e)
    }
}

impl From<crypto::CryptoError> for Fail {
    fn from(e: crypto::CryptoError) -> Self {
        Self::internal(e)
    }
}

type Reply = std::result::Result<(Response, Option<SecureBuf>), Fail>;

fn token() -> Result<String, Fail> {
    Ok(crypto::b64url(&crypto::random_bytes::<32>()?))
}

fn sanitize_label(label: Option<String>, fallback: &str) -> String {
    let l: String = label
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    let l = l.trim();
    if l.is_empty() {
        fallback.to_owned()
    } else {
        l.to_owned()
    }
}

impl Daemon {
    fn lock_state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn web_url(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
    }

    /// Wipes every unlocked key. Returns how many vaults were locked.
    pub fn lock_all(&self, reason: &str) -> usize {
        let mut st = self.lock_state();
        let n = st.unlocked.len();
        st.unlocked.clear();
        st.flows
            .retain(|_, f| !matches!(f.kind, FlowKind::Enroll { .. }));
        if n > 0 {
            log!("locked {n} vault(s): {reason}");
        }
        n
    }

    /// Removes expired keys and flows. Returns true if the daemon is idle.
    fn reap(&self) -> bool {
        let now = Instant::now();
        let mut st = self.lock_state();
        st.unlocked.retain(|_, u| match u.expires {
            Some(t) if t <= now => {
                log!("auto-locked vault {} (time is up)", u.name);
                false
            }
            _ => true,
        });
        let expired: Vec<String> = st
            .flows
            .iter()
            .filter(|(_, f)| now.duration_since(f.created) > FLOW_TTL)
            .map(|(t, _)| t.clone())
            .collect();
        for t in expired {
            if let Some(f) = st.flows.remove(&t) {
                st.results.insert(f.id, (FlowState::Expired, now));
            }
        }
        st.results
            .retain(|_, (_, at)| now.duration_since(*at) < RESULT_TTL);
        st.unlocked.is_empty() && st.flows.is_empty()
    }

    fn statuses(&self) -> Vec<VaultStatus> {
        let now = Instant::now();
        let st = self.lock_state();
        let mut out: Vec<VaultStatus> = st
            .unlocked
            .iter()
            .filter(|(_, u)| u.expires.is_none_or(|t| t > now))
            .map(|(id, u)| VaultStatus {
                vault_id: id.clone(),
                name: u.name.clone(),
                path: u.path.clone(),
                unlocked_at: u
                    .unlocked_at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
                expires_in_secs: u.expires.map(|t| t.duration_since(now).as_secs().max(1)),
            })
            .collect();
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    fn start_flow(&self, vault_path: PathBuf, kind: FlowKind, page: &str) -> Reply {
        let token = token()?;
        let id = token_short()?;
        let flow = Flow {
            id: id.clone(),
            vault_path,
            created: Instant::now(),
            attempts: 0,
            challenge: crypto::random_bytes()?,
            kind,
        };
        let mut st = self.lock_state();
        // Only one pending flow per vault file and kind.
        let same = |f: &Flow| {
            f.vault_path == flow.vault_path
                && std::mem::discriminant(&f.kind) == std::mem::discriminant(&flow.kind)
        };
        let superseded: Vec<String> = st
            .flows
            .iter()
            .filter(|(_, f)| same(f))
            .map(|(t, _)| t.clone())
            .collect();
        for t in superseded {
            if let Some(old) = st.flows.remove(&t) {
                st.results.insert(
                    old.id,
                    (
                        FlowState::Failed {
                            message: "superseded by a newer request".into(),
                        },
                        Instant::now(),
                    ),
                );
            }
        }
        st.flows.insert(token.clone(), flow);
        Ok((
            Response::FlowStarted {
                flow_id: id,
                url: format!("{}/{page}#{token}", self.web_url()),
            },
            None,
        ))
    }

    fn handle(&self, req: Request) -> Reply {
        self.touch();
        match req {
            Request::Ping => Ok((
                Response::Pong {
                    pid: std::process::id(),
                    version: env!("CARGO_PKG_VERSION").into(),
                },
                None,
            )),
            Request::Status => {
                self.reap();
                Ok((
                    Response::Status {
                        vaults: self.statuses(),
                        web_url: self.web_url(),
                    },
                    None,
                ))
            }
            Request::Setup {
                vault_path,
                name,
                label,
            } => {
                let vault_path = vault::absolute(&vault_path)?;
                if vault_path.exists() {
                    return Err(Fail::invalid(format!(
                        "{} already exists",
                        vault_path.display()
                    )));
                }
                match vault_path.parent() {
                    Some(dir) if dir.is_dir() => {}
                    _ => return Err(Fail::invalid("the vault's directory does not exist")),
                }
                let name = match name.filter(|n| !n.trim().is_empty()) {
                    Some(n) => {
                        vault::validate_vault_name(&n).map_err(|e| Fail::invalid(e.to_string()))?
                    }
                    None => vault::default_name(&vault_path),
                };
                let kind = FlowKind::Setup {
                    name,
                    label: sanitize_label(label, "Passkey 1"),
                    user_id: crypto::random_bytes()?,
                    prf_salt: crypto::random_bytes()?,
                };
                self.start_flow(vault_path, kind, "setup")
            }
            Request::Enroll { vault_path, label } => {
                let v = load_vault(&vault_path)?;
                self.require_unlocked(v.id())?;
                let kind = FlowKind::Enroll {
                    vault_id: v.id().to_owned(),
                    label: sanitize_label(label, &format!("Passkey {}", v.file.passkeys.len() + 1)),
                    user_id: crypto::random_bytes()?,
                    prf_salt: crypto::random_bytes()?,
                };
                self.start_flow(v.path, kind, "enroll")
            }
            Request::Unlock {
                vault_path,
                suggest_secs,
            } => {
                let v = load_vault(&vault_path)?;
                if v.file.passkeys.is_empty() {
                    return Err(Fail::invalid("this vault has no passkeys"));
                }
                let kind = FlowKind::Unlock {
                    vault_id: v.id().to_owned(),
                    suggest_secs: suggest_secs.map(|s| s.min(MAX_DURATION.as_secs())),
                };
                self.start_flow(v.path, kind, "unlock")
            }
            Request::FlowStatus { flow_id } => {
                self.reap();
                let st = self.lock_state();
                let state = if st.flows.values().any(|f| f.id == flow_id) {
                    FlowState::Pending
                } else if let Some((s, _)) = st.results.get(&flow_id) {
                    s.clone()
                } else {
                    return Err(Fail::new(ErrorCode::NotFound, "unknown flow"));
                };
                Ok((Response::FlowState { state }, None))
            }
            Request::Get { vault_path, key } => {
                let v = load_vault(&vault_path)?;
                self.reap();
                let entry = v.file.secrets.get(&key).ok_or_else(|| {
                    Fail::new(
                        ErrorCode::NotFound,
                        format!("no secret named {key:?} in {}", v.path.display()),
                    )
                })?;
                let st = self.lock_state();
                let u = st.unlocked.get(v.id()).ok_or_else(|| locked_fail(&v))?;
                let plain = crypto::open_value(&u.key, &u.public, v.id(), &key, &entry.value)
                    .map_err(|e| Fail::internal(format!("{key}: {e}")))?;
                drop(st);
                Ok((Response::Secret { len: plain.len() }, Some(plain)))
            }
            Request::Lock { vault_path } => {
                let count = match vault_path {
                    None => self.lock_all("lock requested"),
                    Some(p) => {
                        let v = load_vault(&p)?;
                        let removed = self.lock_state().unlocked.remove(v.id());
                        if removed.is_some() {
                            log!("locked vault {} (lock requested)", v.name());
                        }
                        usize::from(removed.is_some())
                    }
                };
                Ok((Response::Locked { count }, None))
            }
            Request::Shutdown => {
                self.lock_all("shutdown requested");
                self.shutdown.notify_one();
                Ok((Response::Ok, None))
            }
        }
    }

    fn require_unlocked(&self, vault_id: &str) -> Result<(), Fail> {
        self.reap();
        if self.lock_state().unlocked.contains_key(vault_id) {
            Ok(())
        } else {
            Err(Fail::new(
                ErrorCode::Locked,
                "the vault is locked; run `agentpass unlock` first",
            ))
        }
    }

    // ---- web UI side -------------------------------------------------------

    pub fn flow_info(&self, token: &str) -> Result<proto::FlowInfo, Fail> {
        self.reap();
        let st = self.lock_state();
        let flow = st.flows.get(token).ok_or_else(|| {
            Fail::new(
                ErrorCode::NotFound,
                "this link has expired or was already used; ask for a new one",
            )
        })?;
        let challenge = crypto::b64url(&flow.challenge);
        let rp_id = proto::RP_ID.to_owned();
        Ok(match &flow.kind {
            FlowKind::Setup {
                name,
                label,
                user_id,
                prf_salt,
            } => {
                let vname = name.clone();
                proto::FlowInfo::Setup(proto::RegisterInfo {
                    vault: proto::VaultSummary {
                        name: vname.clone(),
                        path: flow.vault_path.display().to_string(),
                        vault_id: String::new(),
                        secret_count: 0,
                    },
                    rp_id,
                    user_id: crypto::b64url(user_id),
                    user_name: format!("agentpass: {vname}"),
                    challenge,
                    prf_salt: crypto::b64url(prf_salt),
                    exclude_credentials: vec![],
                    suggested_label: label.clone(),
                })
            }
            FlowKind::Enroll {
                label,
                user_id,
                prf_salt,
                ..
            } => {
                let v = load_vault(&flow.vault_path)?;
                proto::FlowInfo::Enroll(proto::RegisterInfo {
                    vault: summary(&v),
                    rp_id,
                    user_id: crypto::b64url(user_id),
                    user_name: format!("agentpass: {}", v.name()),
                    challenge,
                    prf_salt: crypto::b64url(prf_salt),
                    exclude_credentials: v
                        .file
                        .passkeys
                        .iter()
                        .map(|p| p.credential_id.clone())
                        .collect(),
                    suggested_label: label.clone(),
                })
            }
            FlowKind::Unlock { suggest_secs, .. } => {
                let v = load_vault(&flow.vault_path)?;
                proto::FlowInfo::Unlock(proto::UnlockInfo {
                    vault: summary(&v),
                    rp_id,
                    challenge,
                    passkeys: v
                        .file
                        .passkeys
                        .iter()
                        .map(|p| proto::PasskeyDescriptor {
                            label: p.label.clone(),
                            credential_id: p.credential_id.clone(),
                            prf_salt: p.prf_salt.clone(),
                        })
                        .collect(),
                    suggested_duration_secs: *suggest_secs,
                    max_duration_secs: MAX_DURATION.as_secs(),
                })
            }
        })
    }

    pub fn complete_flow(
        &self,
        token: &str,
        completion: proto::FlowCompletion,
    ) -> Result<String, Fail> {
        self.reap();
        self.touch();
        let mut st = self.lock_state();
        let flow = st.flows.get_mut(token).ok_or_else(|| {
            Fail::new(
                ErrorCode::NotFound,
                "this link has expired or was already used; ask for a new one",
            )
        })?;
        flow.attempts += 1;
        let attempts = flow.attempts;
        let result = match completion {
            proto::FlowCompletion::Registered {
                credential_id,
                prf_output,
                label,
            } => {
                let prf = decode_prf(&prf_output)?;
                validate_credential_id(&credential_id)?;
                complete_registration(&mut st, token, &credential_id, &prf, label)
            }
            proto::FlowCompletion::Unlocked {
                credential_id,
                prf_output,
                duration_secs,
            } => {
                let prf = decode_prf(&prf_output)?;
                complete_unlock(&mut st, token, &credential_id, &prf, duration_secs)
            }
        };
        let flow_id = st.flows.get(token).map(|f| f.id.clone());
        match &result {
            Ok(message) => {
                if let Some(f) = st.flows.remove(token) {
                    st.results.insert(
                        f.id,
                        (
                            FlowState::Done {
                                message: message.clone(),
                            },
                            Instant::now(),
                        ),
                    );
                }
                log!("{message}");
            }
            Err(e) if attempts >= FLOW_MAX_ATTEMPTS || e.code == ErrorCode::Internal => {
                st.flows.remove(token);
                if let Some(id) = flow_id {
                    st.results.insert(
                        id,
                        (
                            FlowState::Failed {
                                message: e.message.clone(),
                            },
                            Instant::now(),
                        ),
                    );
                }
                log!("flow failed: {}", e.message);
            }
            Err(e) => log!("flow attempt {attempts} rejected: {}", e.message),
        }
        result
    }
}

fn token_short() -> Result<String, Fail> {
    Ok(crypto::b64url(&crypto::random_bytes::<12>()?))
}

fn locked_fail(v: &Vault) -> Fail {
    Fail::new(
        ErrorCode::Locked,
        format!(
            "vault {} is locked; run `agentpass unlock` and ask the user to open the link",
            v.name()
        ),
    )
}

fn load_vault(path: &Path) -> Result<Vault, Fail> {
    Vault::load(path).map_err(|e| Fail::new(ErrorCode::NotFound, format!("{e:#}")))
}

fn summary(v: &Vault) -> proto::VaultSummary {
    proto::VaultSummary {
        name: v.name(),
        path: v.path.display().to_string(),
        vault_id: v.id().to_owned(),
        secret_count: v.file.secrets.len(),
    }
}

fn decode_prf(b64: &str) -> Result<Zeroizing<Vec<u8>>, Fail> {
    let prf = Zeroizing::new(
        crypto::from_b64url(b64).ok_or_else(|| Fail::invalid("malformed PRF output"))?,
    );
    if prf.len() != PRF_LEN {
        return Err(Fail::invalid("PRF output must be 32 bytes"));
    }
    Ok(prf)
}

fn validate_credential_id(id: &str) -> Result<(), Fail> {
    match crypto::from_b64url(id) {
        Some(raw) if !raw.is_empty() && raw.len() <= 1023 => Ok(()),
        _ => Err(Fail::invalid("malformed credential id")),
    }
}

fn now_rfc3339() -> String {
    humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string()
}

fn complete_registration(
    st: &mut State,
    token: &str,
    credential_id: &str,
    prf: &[u8],
    label: String,
) -> Result<String, Fail> {
    let flow = &st.flows[token];
    match &flow.kind {
        FlowKind::Setup {
            name,
            label: default_label,
            prf_salt,
            ..
        } => {
            if flow.vault_path.exists() {
                return Err(Fail::internal(format!(
                    "{} was created by someone else in the meantime",
                    flow.vault_path.display()
                )));
            }
            let key = PrivateKey::generate()?;
            let vault_id = ulid::Ulid::new().to_string();
            let label = sanitize_label(Some(label), default_label);
            let file = VaultFile {
                version: vault::VERSION,
                vault_id: vault_id.clone(),
                name: name.clone(),
                public_key: crypto::b64(&key.public_key()),
                passkeys: vec![PasskeyEntry {
                    wrapped_private_key: crypto::wrap_private_key(
                        &key,
                        prf,
                        &vault_id,
                        credential_id,
                    )?,
                    label: label.clone(),
                    credential_id: credential_id.to_owned(),
                    prf_salt: crypto::b64url(prf_salt),
                    created: Some(now_rfc3339()),
                }],
                secrets: Default::default(),
            };
            vault::write_atomic(&flow.vault_path, &file)?;
            Ok(format!(
                "Created vault {} with passkey \"{label}\"",
                flow.vault_path.display()
            ))
        }
        FlowKind::Enroll {
            vault_id,
            label: default_label,
            prf_salt,
            ..
        } => {
            let mut v = load_vault(&flow.vault_path)?;
            if v.id() != vault_id {
                return Err(Fail::internal("the vault file changed identity"));
            }
            if v.passkey(credential_id).is_some() {
                return Err(Fail::invalid("this passkey is already enrolled"));
            }
            let u = st.unlocked.get(vault_id).ok_or_else(|| locked_fail(&v))?;
            let label = sanitize_label(Some(label), default_label);
            let wrapped = crypto::wrap_private_key(&u.key, prf, vault_id, credential_id)?;
            // Sanity check: the new wrapping must open with the same PRF.
            crypto::unwrap_private_key(&wrapped, prf, vault_id, credential_id, &u.public)?;
            v.file.passkeys.push(PasskeyEntry {
                label: label.clone(),
                credential_id: credential_id.to_owned(),
                prf_salt: crypto::b64url(prf_salt),
                wrapped_private_key: wrapped,
                created: Some(now_rfc3339()),
            });
            v.save()?;
            Ok(format!("Added passkey \"{label}\" to vault {}", v.name()))
        }
        FlowKind::Unlock { .. } => Err(Fail::invalid(
            "this link is for unlocking, not registration",
        )),
    }
}

fn complete_unlock(
    st: &mut State,
    token: &str,
    credential_id: &str,
    prf: &[u8],
    duration_secs: Option<u64>,
) -> Result<String, Fail> {
    let flow = &st.flows[token];
    let FlowKind::Unlock { vault_id, .. } = &flow.kind else {
        return Err(Fail::invalid("this link is for registering a passkey"));
    };
    let duration = match duration_secs {
        None => None,
        Some(0) => return Err(Fail::invalid("duration must be positive")),
        Some(s) if s > MAX_DURATION.as_secs() => {
            return Err(Fail::invalid(
                "duration is longer than 30 days; choose \"Until locked\" instead",
            ))
        }
        Some(s) => Some(Duration::from_secs(s)),
    };
    let v = load_vault(&flow.vault_path)?;
    if v.id() != vault_id {
        return Err(Fail::internal("the vault file changed identity"));
    }
    let pk = v
        .passkey(credential_id)
        .ok_or_else(|| Fail::invalid("this passkey is not enrolled in the vault"))?;
    let public = v.public_key()?;
    let key = crypto::unwrap_private_key(
        &pk.wrapped_private_key,
        prf,
        vault_id,
        credential_id,
        &public,
    )
    .map_err(|_| {
        Fail::invalid("the passkey did not unlock this vault (wrong passkey or PRF output)")
    })?;
    let label = pk.label.clone();
    let name = v.name();
    st.unlocked.insert(
        vault_id.clone(),
        Unlocked {
            key,
            public,
            path: v.path.clone(),
            name: name.clone(),
            unlocked_at: SystemTime::now(),
            expires: duration.map(|d| Instant::now() + d),
        },
    );
    Ok(match duration {
        Some(d) => format!(
            "Unlocked vault {name} with \"{label}\" for {}",
            humantime::format_duration(d)
        ),
        None => format!("Unlocked vault {name} with \"{label}\" until locked"),
    })
}

// ---- process / server plumbing ---------------------------------------------

pub fn run() -> Result<()> {
    secmem::harden_daemon().context("hardening the daemon process")?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(serve())
}

fn acquire_lock(dir: &Path) -> Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("agent.lock"))?;
    // SAFETY: valid fd owned by `f`.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another agentpass daemon is already running");
    }
    Ok(f)
}

async fn bind_web() -> Result<tokio::net::TcpListener> {
    let port = match std::env::var("AGENTPASS_PORT") {
        Ok(p) => p
            .parse::<u16>()
            .context("AGENTPASS_PORT must be a port number")?,
        Err(_) => DEFAULT_PORT,
    };
    match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => Ok(l),
        Err(e) if port != 0 => {
            log!("port {port} unavailable ({e}); using a random port");
            Ok(tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?)
        }
        Err(e) => Err(e.into()),
    }
}

async fn serve() -> Result<()> {
    let dir = ipc::ensure_runtime_dir()?;
    let _lock = acquire_lock(&dir)?;
    let sock_path = ipc::socket_path();
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("binding {}", sock_path.display()))?;
    std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    let web = bind_web().await?;
    let port = web.local_addr()?.port();
    let d = Arc::new(Daemon {
        state: Mutex::new(State::default()),
        port,
        last_activity: Mutex::new(Instant::now()),
        shutdown: tokio::sync::Notify::new(),
    });
    log!(
        "started (version {}), socket {}, web UI {}",
        env!("CARGO_PKG_VERSION"),
        sock_path.display(),
        d.web_url()
    );

    tokio::spawn(web::serve(d.clone(), web));
    tokio::spawn(reaper(d.clone()));
    watch::spawn(d.clone());

    // SAFETY: geteuid never fails.
    let euid = unsafe { libc::geteuid() };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    loop {
        tokio::select! {
            conn = listener.accept() => {
                let (stream, _) = match conn {
                    Ok(c) => c,
                    Err(e) => { log!("accept failed: {e}"); continue; }
                };
                match stream.peer_cred() {
                    Ok(cred) if cred.uid() == euid => {
                        let d = d.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(&d, stream).await {
                                log!("client error: {e:#}");
                            }
                        });
                    }
                    Ok(cred) => log!("rejected connection from uid {}", cred.uid()),
                    Err(e) => log!("rejected connection: no peer credentials ({e})"),
                }
            }
            _ = d.shutdown.notified() => break,
            _ = term.recv() => { d.lock_all("SIGTERM"); break; }
            _ = int.recv() => { d.lock_all("SIGINT"); break; }
            _ = hup.recv() => { d.lock_all("SIGHUP"); break; }
        }
    }
    d.lock_all("daemon exiting");
    let _ = std::fs::remove_file(&sock_path);
    log!("stopped");
    Ok(())
}

async fn reaper(d: Arc<Daemon>) {
    let idle_exit = std::env::var("AGENTPASS_IDLE_EXIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_IDLE_EXIT);
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tick.tick().await;
        let idle = d.reap();
        let last = *d.last_activity.lock().unwrap_or_else(|p| p.into_inner());
        if idle && !idle_exit.is_zero() && last.elapsed() > idle_exit {
            log!("idle with nothing unlocked; exiting");
            d.shutdown.notify_one();
            return;
        }
    }
}

async fn handle_conn(d: &Daemon, mut stream: UnixStream) -> Result<()> {
    let (read, mut write) = stream.split();
    let mut line = Vec::new();
    let mut reader = BufReader::new(read.take(ipc::MAX_HEADER as u64));
    tokio::time::timeout(Duration::from_secs(10), reader.read_until(b'\n', &mut line))
        .await
        .context("request timed out")??;
    if line.is_empty() {
        // A liveness probe (`Client::existing`) that connected and left.
        return Ok(());
    }
    let req: Request = serde_json::from_slice(&line).context("malformed request")?;
    let (resp, secret) = match d.handle(req) {
        Ok(r) => r,
        Err(f) => (
            Response::Error {
                code: f.code,
                message: f.message,
            },
            None,
        ),
    };
    let mut header = serde_json::to_vec(&resp)?;
    header.push(b'\n');
    write.write_all(&header).await?;
    if let Some(secret) = secret {
        write.write_all(secret.as_slice()).await?;
        // `secret` is wiped and unmapped when dropped here.
    }
    write.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
