//! CLI ⇄ daemon protocol over a Unix socket.
//!
//! One request per connection. The request is a single JSON line (requests
//! never carry plaintext secrets). The response is a single JSON line; for
//! [`Response::Secret`] it is followed by exactly `len` raw bytes, which the
//! client reads straight into locked memory.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::secmem::SecureBuf;

pub const MAX_HEADER: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Status,
    Setup {
        vault_path: PathBuf,
        name: Option<String>,
        label: Option<String>,
    },
    Enroll {
        vault_path: PathBuf,
        label: Option<String>,
    },
    Unlock {
        vault_path: PathBuf,
        suggest_secs: Option<u64>,
    },
    FlowStatus {
        flow_id: String,
    },
    Get {
        vault_path: PathBuf,
        key: String,
    },
    Lock {
        vault_path: Option<PathBuf>,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong {
        pid: u32,
        version: String,
    },
    Status {
        vaults: Vec<VaultStatus>,
        web_url: String,
    },
    FlowStarted {
        flow_id: String,
        url: String,
    },
    FlowState {
        state: FlowState,
    },
    /// Followed by `len` raw bytes.
    Secret {
        len: usize,
    },
    Locked {
        count: usize,
    },
    Ok,
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Locked,
    NotFound,
    Invalid,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FlowState {
    Pending,
    Done { message: String },
    Failed { message: String },
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatus {
    pub vault_id: String,
    pub name: String,
    pub path: PathBuf,
    /// Seconds since the Unix epoch.
    pub unlocked_at: u64,
    /// `None` = until locked.
    pub expires_in_secs: Option<u64>,
}

/// Directory holding the daemon socket, lock file and log.
pub fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("AGENTPASS_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("agentpass");
    }
    // SAFETY: getuid never fails.
    let uid = unsafe { libc::getuid() };
    std::env::temp_dir().join(format!("agentpass-{uid}"))
}

pub fn socket_path() -> PathBuf {
    runtime_dir().join("agent.sock")
}

/// Creates the runtime directory with mode 0700 and verifies that nobody
/// else can access it.
pub fn ensure_runtime_dir() -> Result<PathBuf> {
    let dir = runtime_dir();
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    check_private_dir(&dir)?;
    Ok(dir)
}

pub fn check_private_dir(dir: &Path) -> Result<()> {
    let meta = std::fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    // SAFETY: geteuid never fails.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        bail!("{} is not owned by the current user", dir.display());
    }
    if meta.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting permissions of {}", dir.display()))?;
    }
    Ok(())
}

/// Error returned by daemon requests, carrying the CLI exit code.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct DaemonError {
    pub code: ErrorCode,
    pub message: String,
}

pub struct Client {
    path: PathBuf,
}

impl Client {
    /// Connects to the running daemon, if any.
    pub fn existing() -> Option<Self> {
        let path = socket_path();
        UnixStream::connect(&path).ok().map(|_| Self { path })
    }

    /// Connects to the daemon, starting it in the background if needed.
    pub fn connect_or_spawn() -> Result<Self> {
        if let Some(c) = Self::existing() {
            return Ok(c);
        }
        let dir = ensure_runtime_dir()?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("daemon.log"))?;
        let exe = std::env::current_exe().context("locating agentpass binary")?;
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(log);
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child = cmd.spawn().context("starting agentpass daemon")?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(c) = Self::existing() {
                // The daemon keeps running in its own session after we exit.
                return Ok(c);
            }
            if let Ok(Some(status)) = child.try_wait() {
                // Another daemon may have won the race.
                if let Some(c) = Self::existing() {
                    return Ok(c);
                }
                bail!(
                    "agentpass daemon exited ({status}); see {}",
                    dir.join("daemon.log").display()
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        bail!("timed out waiting for the agentpass daemon to start")
    }

    fn send(&self, req: &Request) -> Result<(UnixStream, Response)> {
        let mut stream = UnixStream::connect(&self.path)
            .with_context(|| format!("connecting to {}", self.path.display()))?;
        let mut line = serde_json::to_vec(req)?;
        line.push(b'\n');
        stream.write_all(&line)?;
        let header = read_line(&mut stream)?;
        let resp: Response = serde_json::from_slice(&header).context("invalid daemon response")?;
        if let Response::Error { code, message } = resp {
            return Err(DaemonError { code, message }.into());
        }
        Ok((stream, resp))
    }

    pub fn request(&self, req: &Request) -> Result<Response> {
        Ok(self.send(req)?.1)
    }

    /// Fetches a secret value into locked memory.
    pub fn get_secret(&self, vault_path: &Path, key: &str) -> Result<SecureBuf> {
        let (mut stream, resp) = self.send(&Request::Get {
            vault_path: vault_path.to_owned(),
            key: key.to_owned(),
        })?;
        let Response::Secret { len } = resp else {
            bail!("unexpected daemon response");
        };
        if len > crate::crypto::MAX_VALUE_LEN {
            bail!("daemon sent an oversized value");
        }
        let mut buf = SecureBuf::new(len)?;
        stream.read_exact(buf.as_mut_slice())?;
        Ok(buf)
    }
}

/// Reads one `\n`-terminated line byte by byte, so no secret bytes that
/// follow end up in an unmanaged buffer.
fn read_line(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            bail!("daemon closed the connection");
        }
        if byte[0] == b'\n' {
            return Ok(out);
        }
        if out.len() >= MAX_HEADER {
            bail!("daemon response header too long");
        }
        out.push(byte[0]);
    }
}
