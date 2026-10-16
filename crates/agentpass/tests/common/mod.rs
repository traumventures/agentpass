//! Test harness: an isolated daemon plus a vault whose passkey PRF output is
//! known, so tests can unlock through the real HTTP API without a browser.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use agentpass::crypto::{self, PrivateKey};
use agentpass::vault::{self, PasskeyEntry, VaultFile};

pub const PRF: [u8; 32] = [0x5a; 32];
pub const CRED: &str = "dGVzdC1jcmVkZW50aWFs";

pub struct Sandbox {
    pub dir: tempfile::TempDir,
    pub port: u16,
    pub daemon: Option<Child>,
    pub key: Vec<u8>,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Sandbox {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = PrivateKey::generate().unwrap();
        let vault_id = "01TESTVAULT".to_owned();
        let file = VaultFile {
            version: vault::VERSION,
            vault_id: vault_id.clone(),
            name: "test".into(),
            public_key: crypto::b64(&key.public_key()),
            passkeys: vec![PasskeyEntry {
                label: "test key".into(),
                credential_id: CRED.into(),
                prf_salt: crypto::b64url(&[1; 32]),
                wrapped_private_key: crypto::wrap_private_key(&key, &PRF, &vault_id, CRED).unwrap(),
                created: None,
            }],
            secrets: Default::default(),
        };
        vault::write_atomic(&dir.path().join("secrets.agentpass.toml"), &file).unwrap();
        Self {
            port: free_port(),
            key: key.expose().to_vec(),
            dir,
            daemon: None,
        }
    }

    pub fn vault(&self) -> PathBuf {
        self.dir.path().join("secrets.agentpass.toml")
    }

    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agentpass"));
        c.args(args)
            .current_dir(self.dir.path())
            .env("AGENTPASS_RUNTIME_DIR", self.dir.path().join("run"))
            .env("AGENTPASS_PORT", self.port.to_string())
            .env("AGENTPASS_VAULT", self.vault())
            .env_remove("XDG_SESSION_ID");
        c
    }

    pub fn run(&self, args: &[&str], input: Option<&[u8]>) -> Output {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if let Some(i) = input {
            stdin.write_all(i).unwrap();
        }
        drop(stdin);
        child.wait_with_output().unwrap()
    }

    /// Starts the daemon as a direct child so tests know its pid.
    pub fn start_daemon(&mut self) -> u32 {
        let child = self
            .cmd(&["daemon"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        self.daemon = Some(child);
        let sock = self.dir.path().join("run/agent.sock");
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(&sock).is_err() {
            assert!(Instant::now() < deadline, "daemon did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        pid
    }

    /// Requests an unlock with the CLI and completes it over HTTP, exactly
    /// as the web UI would after the passkey ceremony.
    pub fn unlock(&self, duration_secs: Option<u64>) {
        let out = self.run(&["unlock"], None);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let url = String::from_utf8(out.stdout).unwrap();
        let body = serde_json::json!({
            "kind": "unlocked",
            "credential_id": CRED,
            "prf_output": crypto::b64url(&PRF),
            "duration_secs": duration_secs,
        })
        .to_string();
        let (status, resp) = http_complete(&url, &body);
        assert_eq!(status, 200, "{resp}");
    }
}

/// Posts a flow completion for the link `url` (as printed by the CLI) to the
/// daemon that issued it. The port comes from the link because the daemon
/// falls back to a random port when the requested one is taken.
pub fn http_complete(url: &str, body: &str) -> (u16, String) {
    let url = url.trim();
    let (base, token) = url.split_once('#').expect("link has a token");
    let port: u16 = base
        .trim_start_matches("http://localhost:")
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "POST /api/flow/complete HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: http://localhost:{port}\r\n\
         x-agentpass-token: {token}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status = resp[9..12].parse().unwrap();
    (status, resp)
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = self.run(&["daemon", "--stop"], None);
        if let Some(mut c) = self.daemon.take() {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = c.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
