//! Command-line interface.

use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use crate::crypto::MAX_VALUE_LEN;
use crate::ipc::{Client, DaemonError, ErrorCode, FlowState, Request, Response, VaultStatus};
use crate::secmem::{self, SecureBuf};
use crate::vault::{self, Vault};

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_LOCKED: i32 = 3;
pub const EXIT_NOT_FOUND: i32 = 4;
pub const EXIT_TIMEOUT: i32 = 5;

const AFTER_HELP: &str = "\
Typical agent workflow:
  agentpass get GITHUB_TOKEN          # exit code 3 means the vault is locked
  agentpass unlock                    # prints a link; give it to the user
  agentpass wait                      # blocks until the user has unlocked
  agentpass get GITHUB_TOKEN | gh auth login --with-token
  agentpass run -e NPM_TOKEN -- npm publish

Never capture a secret into your own context: pipe `get` straight into the
command that needs it, or use `run` to pass it as an environment variable.

Exit codes: 0 ok, 1 error, 2 usage, 3 locked, 4 not found, 5 timeout.";

#[derive(Parser)]
#[command(name = "agentpass", version, about = "A passkey-unlocked password manager for AI agents", after_help = AFTER_HELP)]
struct Cli {
    /// Vault file or directory (default: nearest agentpass.toml).
    #[arg(long, global = true, env = "AGENTPASS_VAULT", value_name = "PATH")]
    vault: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault and register its first passkey in the browser.
    Setup {
        /// Display name of the vault (default: directory name).
        #[arg(long)]
        name: Option<String>,
        /// Label for the passkey.
        #[arg(long)]
        label: Option<String>,
        #[command(flatten)]
        browser: BrowserArgs,
    },
    /// Manage the passkeys that can unlock the vault.
    #[command(subcommand)]
    Passkey(PasskeyCommand),
    /// Encrypt and store a secret. Works while locked. Reads the value from
    /// stdin, or prompts for it without echo.
    Set {
        key: String,
        /// Description (stored in plain text).
        #[arg(short, long)]
        description: Option<String>,
        /// Keep a trailing newline from piped input.
        #[arg(long)]
        raw: bool,
    },
    /// List secret names and descriptions. Works while locked.
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        json: bool,
    },
    /// Remove a secret. Works while locked.
    #[command(alias = "remove")]
    Rm { key: String },
    /// Request an unlock: prints a link for the user to open; returns at once.
    Unlock {
        /// Suggest how long to stay unlocked (e.g. 30m, 1h, 8h, or "forever").
        /// The user decides on the page.
        #[arg(long, value_name = "DURATION")]
        suggest: Option<String>,
        /// Open the link in the default browser.
        #[arg(long)]
        open: bool,
        /// Request a new unlock even if the vault is already unlocked.
        #[arg(long)]
        force: bool,
    },
    /// Block until the vault is unlocked.
    Wait {
        /// Give up after this long (exit code 5). "0" waits forever.
        #[arg(long, default_value = "10m", value_name = "DURATION")]
        timeout: String,
    },
    /// Write a secret's value to stdout, for piping into another command.
    Get {
        key: String,
        /// Allow printing to a terminal.
        #[arg(long)]
        reveal: bool,
    },
    /// Run a command with secrets in its environment.
    #[command(arg_required_else_help = true)]
    Run {
        /// Secret to export: KEY, or NAME=KEY to use another variable name.
        #[arg(short = 'e', long = "env", value_name = "[NAME=]KEY", required = true)]
        env: Vec<String>,
        /// Command and arguments.
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// Lock the vault now (wipes its key from memory).
    Lock {
        /// Lock every unlocked vault.
        #[arg(long)]
        all: bool,
    },
    /// Show whether the vault is unlocked and for how long. Exit code 3 if locked.
    Status {
        /// Show every unlocked vault.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run the background daemon (started automatically).
    #[command(hide = true)]
    Daemon {
        /// Stop the running daemon (locks everything).
        #[arg(long)]
        stop: bool,
    },
}

#[derive(Subcommand)]
enum PasskeyCommand {
    /// Register another passkey (vault must be unlocked).
    Add {
        #[arg(long)]
        label: Option<String>,
        #[command(flatten)]
        browser: BrowserArgs,
    },
    /// List enrolled passkeys.
    #[command(alias = "ls")]
    List,
    /// Remove a passkey by label or credential id (vault must be unlocked).
    #[command(alias = "rm")]
    Remove { passkey: String },
}

#[derive(Args)]
struct BrowserArgs {
    /// Open the link in the default browser.
    #[arg(long)]
    open: bool,
    /// How long to wait for the browser step.
    #[arg(long, default_value = "15m", value_name = "DURATION")]
    timeout: String,
}

/// An error with a specific exit code.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct Exit {
    code: i32,
    message: String,
}

fn exit(code: i32, message: impl Into<String>) -> anyhow::Error {
    Exit {
        code,
        message: message.into(),
    }
    .into()
}

pub fn main() -> i32 {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            let code = if let Some(x) = e.downcast_ref::<Exit>() {
                x.code
            } else if let Some(d) = e.downcast_ref::<DaemonError>() {
                match d.code {
                    ErrorCode::Locked => EXIT_LOCKED,
                    ErrorCode::NotFound => EXIT_NOT_FOUND,
                    ErrorCode::Invalid => EXIT_USAGE,
                    ErrorCode::Internal => EXIT_ERROR,
                }
            } else {
                EXIT_ERROR
            };
            eprintln!("agentpass: {e:#}");
            code
        }
    }
}

fn parse_duration(s: &str) -> Result<Duration> {
    humantime::parse_duration(s.trim())
        .map_err(|e| exit(EXIT_USAGE, format!("invalid duration {s:?}: {e}")))
}

fn fmt_secs(secs: u64) -> String {
    // Round to the minute above one hour, to the second below.
    let secs = if secs >= 3600 { secs / 60 * 60 } else { secs };
    humantime::format_duration(Duration::from_secs(secs)).to_string()
}

fn locate(cli_vault: Option<&Path>) -> Result<Vault> {
    Vault::load(&vault::locate(cli_vault)?)
}

fn run(cli: Cli) -> Result<i32> {
    let vault_arg = cli.vault.as_deref();
    match cli.command {
        Command::Setup {
            name,
            label,
            browser,
        } => {
            let path = vault::new_vault_path(vault_arg)?;
            if path.exists() {
                bail!("{} already exists", path.display());
            }
            let client = Client::connect_or_spawn()?;
            let resp = client.request(&Request::Setup {
                vault_path: path.clone(),
                name,
                label,
            })?;
            browser_flow(
                &client,
                resp,
                &browser,
                "create the vault and register a passkey",
            )
        }
        Command::Passkey(PasskeyCommand::Add { label, browser }) => {
            let v = locate(vault_arg)?;
            let client = Client::existing().ok_or_else(|| locked(&v))?;
            let resp = client.request(&Request::Enroll {
                vault_path: v.path.clone(),
                label,
            })?;
            browser_flow(&client, resp, &browser, "register an additional passkey")
        }
        Command::Passkey(PasskeyCommand::List) => {
            let v = locate(vault_arg)?;
            for p in &v.file.passkeys {
                let id = &p.credential_id;
                let short = &id[..id.len().min(16)];
                match &p.created {
                    Some(c) => println!("{}\t{short}…\tadded {c}", p.label),
                    None => println!("{}\t{short}…", p.label),
                }
            }
            Ok(EXIT_OK)
        }
        Command::Passkey(PasskeyCommand::Remove { passkey }) => {
            let mut v = locate(vault_arg)?;
            if unlocked_status(&v).is_none() {
                return Err(locked(&v));
            }
            let matches: Vec<usize> = v
                .file
                .passkeys
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    p.label == passkey
                        || p.credential_id == passkey
                        || p.credential_id.starts_with(&passkey) && passkey.len() >= 8
                })
                .map(|(i, _)| i)
                .collect();
            match matches.as_slice() {
                [] => Err(exit(
                    EXIT_NOT_FOUND,
                    format!("no passkey matches {passkey:?}"),
                )),
                [_] if v.file.passkeys.len() == 1 => {
                    bail!("refusing to remove the only passkey; add another one first")
                }
                [i] => {
                    let removed = v.file.passkeys.remove(*i);
                    v.save()?;
                    eprintln!("Removed passkey \"{}\"", removed.label);
                    Ok(EXIT_OK)
                }
                _ => Err(exit(
                    EXIT_USAGE,
                    format!("{passkey:?} matches several passkeys; use the credential id"),
                )),
            }
        }
        Command::Set {
            key,
            description,
            raw,
        } => {
            vault::validate_key_name(&key).map_err(|e| exit(EXIT_USAGE, e.to_string()))?;
            let mut v = locate(vault_arg)?;
            secmem::harden_client();
            let value = read_value(&key, raw)?;
            let existed = v.file.secrets.contains_key(&key);
            v.set_secret(&key, value.as_slice(), description)?;
            v.save()?;
            eprintln!(
                "{} {key} ({} bytes, encrypted) in {}",
                if existed { "Updated" } else { "Stored" },
                value.len(),
                v.path.display()
            );
            Ok(EXIT_OK)
        }
        Command::List { json } => {
            let v = locate(vault_arg)?;
            if json {
                let list: Vec<_> = v
                    .file
                    .secrets
                    .iter()
                    .map(|(k, s)| serde_json::json!({"key": k, "description": s.description}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                let width = v.file.secrets.keys().map(|k| k.len()).max().unwrap_or(0);
                for (k, s) in &v.file.secrets {
                    match &s.description {
                        Some(d) => println!("{k:width$}  {d}"),
                        None => println!("{k}"),
                    }
                }
            }
            Ok(EXIT_OK)
        }
        Command::Rm { key } => {
            let mut v = locate(vault_arg)?;
            if v.file.secrets.remove(&key).is_none() {
                return Err(exit(EXIT_NOT_FOUND, format!("no secret named {key:?}")));
            }
            v.save()?;
            eprintln!("Removed {key}");
            Ok(EXIT_OK)
        }
        Command::Unlock {
            suggest,
            open,
            force,
        } => {
            let v = locate(vault_arg)?;
            let suggest_secs = match suggest.as_deref().map(str::trim) {
                None => None,
                Some("forever" | "until-locked" | "never") => Some(0),
                Some(s) => Some(parse_duration(s)?.as_secs().max(60)),
            };
            let client = Client::connect_or_spawn()?;
            if !force {
                if let Some(s) = status_of(&client, &v)? {
                    eprintln!(
                        "Vault {} is already unlocked ({}).",
                        v.name(),
                        describe_expiry(&s)
                    );
                    return Ok(EXIT_OK);
                }
            }
            let Response::FlowStarted { url, .. } = client.request(&Request::Unlock {
                vault_path: v.path.clone(),
                suggest_secs,
            })?
            else {
                bail!("unexpected daemon response");
            };
            eprintln!(
                "Ask the user to open this link and unlock vault \"{}\" with their passkey:",
                v.name()
            );
            println!("{url}");
            eprintln!("Then run `agentpass wait` to block until it is unlocked.");
            if open {
                open_browser(&url);
            }
            Ok(EXIT_OK)
        }
        Command::Wait { timeout } => {
            let v = locate(vault_arg)?;
            let timeout = parse_duration(&timeout)?;
            let deadline = (!timeout.is_zero()).then(|| Instant::now() + timeout);
            loop {
                if let Some(s) = unlocked_status(&v) {
                    eprintln!("Vault {} is unlocked ({}).", v.name(), describe_expiry(&s));
                    return Ok(EXIT_OK);
                }
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    return Err(exit(
                        EXIT_TIMEOUT,
                        format!("timed out waiting for vault {} to be unlocked", v.name()),
                    ));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        Command::Get { key, reveal } => {
            let stdout = std::io::stdout();
            let tty = stdout.is_terminal();
            if tty && !reveal {
                return Err(exit(
                    EXIT_USAGE,
                    "refusing to print a secret to a terminal; pipe it into a command, use `agentpass run`, or pass --reveal",
                ));
            }
            let v = locate(vault_arg)?;
            secmem::harden_client();
            let client = Client::existing().ok_or_else(|| locked(&v))?;
            let value = client.get_secret(&v.path, &key)?;
            let mut out = stdout.lock();
            out.write_all(value.as_slice())?;
            if tty {
                out.write_all(b"\n")?;
            }
            out.flush()?;
            Ok(EXIT_OK)
        }
        Command::Run { env, command } => {
            let v = locate(vault_arg)?;
            let mut mappings = Vec::new();
            for spec in &env {
                let (name, key) = spec.split_once('=').unwrap_or((spec, spec));
                if name.is_empty()
                    || name.starts_with(|c: char| c.is_ascii_digit())
                    || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    return Err(exit(
                        EXIT_USAGE,
                        format!("invalid environment variable name {name:?}; use NAME=KEY"),
                    ));
                }
                mappings.push((name.to_owned(), key.to_owned()));
            }
            let _ = secmem::deny_same_user_inspection();
            let client = Client::existing().ok_or_else(|| locked(&v))?;
            let mut values: Vec<(String, SecureBuf)> = Vec::new();
            for (name, key) in mappings {
                let value = client.get_secret(&v.path, &key)?;
                if value.as_slice().contains(&0) {
                    bail!(
                        "{key} contains a NUL byte and cannot be passed as an environment variable"
                    );
                }
                values.push((name, value));
            }
            let mut cmd = std::process::Command::new(&command[0]);
            cmd.args(&command[1..]);
            for (name, value) in &values {
                cmd.env(name, std::ffi::OsStr::from_bytes(value.as_slice()));
            }
            drop(values);
            use std::os::unix::process::CommandExt;
            // Replaces this process: no shell, no temp files, and the
            // plaintext copies held by `cmd` vanish with our address space.
            let err = cmd.exec();
            bail!("running {:?}: {err}", command[0])
        }
        Command::Lock { all } => {
            let vault_path = if all {
                None
            } else {
                Some(locate(vault_arg)?.path)
            };
            let Some(client) = Client::existing() else {
                eprintln!("Nothing is unlocked.");
                return Ok(EXIT_OK);
            };
            if let Response::Locked { count } = client.request(&Request::Lock { vault_path })? {
                eprintln!(
                    "{}",
                    match count {
                        0 => "Nothing was unlocked.".to_owned(),
                        1 if !all => "Locked.".to_owned(),
                        n => format!("Locked {n} vault(s)."),
                    }
                );
            }
            Ok(EXIT_OK)
        }
        Command::Status { all, json } => {
            let all_status = || -> Result<Vec<VaultStatus>> {
                Ok(match Client::existing() {
                    Some(c) => match c.request(&Request::Status)? {
                        Response::Status { vaults, .. } => vaults,
                        _ => vec![],
                    },
                    None => vec![],
                })
            };
            if all {
                let list = all_status()?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&list)?);
                } else if list.is_empty() {
                    println!("No vault is unlocked.");
                } else {
                    for s in &list {
                        println!("{}\t{}\t{}", s.name, s.path.display(), describe_expiry(s));
                    }
                }
                return Ok(if list.is_empty() {
                    EXIT_LOCKED
                } else {
                    EXIT_OK
                });
            }
            let v = locate(vault_arg)?;
            let s = unlocked_status(&v);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "vault": v.name(),
                        "path": v.path,
                        "vault_id": v.id(),
                        "unlocked": s.is_some(),
                        "expires_in_secs": s.as_ref().and_then(|s| s.expires_in_secs),
                        "secrets": v.file.secrets.len(),
                        "passkeys": v.file.passkeys.len(),
                    }))?
                );
            } else {
                println!("vault:    {} ({})", v.name(), v.path.display());
                println!("secrets:  {}", v.file.secrets.len());
                println!("passkeys: {}", v.file.passkeys.len());
                match &s {
                    Some(s) => println!("state:    unlocked, {}", describe_expiry(s)),
                    None => println!("state:    locked"),
                }
            }
            Ok(if s.is_some() { EXIT_OK } else { EXIT_LOCKED })
        }
        Command::Daemon { stop } => {
            if stop {
                match Client::existing() {
                    Some(c) => {
                        c.request(&Request::Shutdown)?;
                        eprintln!("Daemon stopped.");
                    }
                    None => eprintln!("Daemon is not running."),
                }
                return Ok(EXIT_OK);
            }
            crate::daemon::run()?;
            Ok(EXIT_OK)
        }
    }
}

fn locked(v: &Vault) -> anyhow::Error {
    exit(
        EXIT_LOCKED,
        format!(
            "vault {} is locked; run `agentpass unlock`, give the user the link, then `agentpass wait`",
            v.name()
        ),
    )
}

fn describe_expiry(s: &VaultStatus) -> String {
    match s.expires_in_secs {
        Some(secs) => format!("locks in {}", fmt_secs(secs)),
        None => "until locked".into(),
    }
}

fn status_of(client: &Client, v: &Vault) -> Result<Option<VaultStatus>> {
    Ok(match client.request(&Request::Status)? {
        Response::Status { vaults, .. } => vaults.into_iter().find(|s| s.vault_id == v.id()),
        _ => None,
    })
}

fn unlocked_status(v: &Vault) -> Option<VaultStatus> {
    Client::existing().and_then(|c| status_of(&c, v).ok().flatten())
}

fn open_browser(url: &str) {
    if let Err(e) = open::that_detached(url) {
        eprintln!("agentpass: could not open a browser ({e}); open the link manually");
    }
}

fn browser_flow(client: &Client, resp: Response, browser: &BrowserArgs, what: &str) -> Result<i32> {
    let Response::FlowStarted { flow_id, url } = resp else {
        bail!("unexpected daemon response");
    };
    let timeout = parse_duration(&browser.timeout)?;
    eprintln!("Open this link in a browser to {what}:");
    println!("{url}");
    if browser.open {
        open_browser(&url);
    }
    eprintln!("Waiting for the browser…");
    let deadline = Instant::now() + timeout;
    loop {
        match client.request(&Request::FlowStatus {
            flow_id: flow_id.clone(),
        })? {
            Response::FlowState {
                state: FlowState::Done { message },
            } => {
                eprintln!("{message}");
                return Ok(EXIT_OK);
            }
            Response::FlowState {
                state: FlowState::Failed { message },
            } => bail!("{message}"),
            Response::FlowState {
                state: FlowState::Expired,
            } => {
                return Err(exit(EXIT_TIMEOUT, "the link expired"));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(exit(EXIT_TIMEOUT, "timed out waiting for the browser"));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Reads a secret value into locked memory: a hidden prompt on a terminal,
/// otherwise all of stdin (minus one trailing newline unless `raw`).
fn read_value(key: &str, raw: bool) -> Result<SecureBuf> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        let value = zeroize::Zeroizing::new(
            rpassword::prompt_password(format!("Value for {key}: ")).context("reading value")?,
        );
        if value.is_empty() {
            return Err(exit(EXIT_USAGE, "empty value"));
        }
        return Ok(SecureBuf::from_slice(value.as_bytes())?);
    }
    // Grow by doubling (each old buffer is wiped when dropped), so typical
    // values need little locked memory even under a small `ulimit -l`.
    let too_large = || {
        exit(
            EXIT_USAGE,
            format!("value is larger than {MAX_VALUE_LEN} bytes"),
        )
    };
    let mut buf = SecureBuf::new(4096)?;
    let mut len = 0;
    let mut input = stdin.lock();
    loop {
        if len == buf.len() {
            if len > MAX_VALUE_LEN {
                return Err(too_large());
            }
            let mut bigger = SecureBuf::new((len * 2).min(MAX_VALUE_LEN + 1))?;
            bigger.as_mut_slice()[..len].copy_from_slice(buf.as_slice());
            buf = bigger;
        }
        let n = input.read(&mut buf.as_mut_slice()[len..])?;
        if n == 0 {
            break;
        }
        len += n;
    }
    if len > MAX_VALUE_LEN {
        return Err(too_large());
    }
    if !raw {
        if buf.as_slice()[..len].ends_with(b"\r\n") {
            len -= 2;
        } else if buf.as_slice()[..len].ends_with(b"\n") {
            len -= 1;
        }
    }
    buf.truncate(len);
    Ok(buf)
}
