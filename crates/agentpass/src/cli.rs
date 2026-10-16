//! Command-line interface.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};

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

Teach your coding agent: `agentpass init-skill` (or `agentpass skill`).

Secrets are only ever added or changed in the browser: `agentpass request KEY`
(you propose, the user fills in the value) or `agentpass edit` (the user's editor).

Never capture a secret into your own context: pipe `get` straight into the
command that needs it, or use `run` to pass it as an environment variable.

Exit codes: 0 ok, 1 error, 2 usage, 3 locked, 4 not found, 5 timeout.";

#[derive(Parser)]
#[command(name = "agentpass", version, about = "A passkey-unlocked password manager for AI agents", after_help = AFTER_HELP)]
struct Cli {
    /// Vault file, relative to the current directory (or a name: `prod` =
    /// prod.agentpass.toml). Needed when a directory has several vaults.
    /// Default: the only *.agentpass.toml in the current directory or the
    /// nearest parent.
    #[arg(
        long = "file",
        short = 'f',
        visible_alias = "vault",
        global = true,
        env = "AGENTPASS_FILE",
        value_name = "PATH"
    )]
    file: Option<PathBuf>,
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
    /// Open the secrets editor in the browser: add, change, rename and
    /// delete secrets and folders (asks for your passkey). This is the only
    /// way to change secrets.
    Edit {
        #[command(flatten)]
        browser: BrowserArgs,
    },
    /// Ask the user for one secret. Opens a page where the user enters the
    /// value and can change the suggested name, folder and description.
    /// Blocks until done; prints the final secret name on stdout.
    Request {
        /// Suggested name, with folders if any (e.g. production/STRIPE_KEY).
        key: String,
        /// Suggested description.
        #[arg(short, long)]
        description: Option<String>,
        /// Why the secret is needed (shown to the user).
        #[arg(long)]
        reason: Option<String>,
        #[command(flatten)]
        browser: BrowserArgs,
    },
    /// List secret names and descriptions. Works while locked.
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        json: bool,
    },
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
        /// Wait for a browser step (setup, request, edit, passkey add) by
        /// the ID it printed, instead of an unlock. Prints its result, e.g.
        /// the final name of a requested secret.
        #[arg(value_name = "FLOW_ID")]
        flow: Option<String>,
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
    /// Show the vault's name, or rename it.
    Name {
        /// New name (1 to 64 characters).
        new_name: Option<String>,
    },
    /// Print the agent skill (SKILL.md) that teaches coding agents to use
    /// agentpass safely.
    Skill,
    /// Install the agent skill for Claude Code, Codex, Cursor, Copilot,
    /// Gemini CLI or OpenCode (interactive unless flags are given).
    InitSkill {
        /// Agent to install for (repeatable).
        #[arg(long = "tool", value_enum, value_name = "AGENT")]
        tools: Vec<crate::skill::Tool>,
        /// Install for every supported agent.
        #[arg(long, conflicts_with = "tools")]
        all: bool,
        /// Install into your home directory (all projects).
        #[arg(long, conflicts_with = "project")]
        global: bool,
        /// Install into the current project (git root).
        #[arg(long)]
        project: bool,
        /// Don't ask for confirmation.
        #[arg(short, long)]
        yes: bool,
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
    /// Block until the browser step is done instead of returning at once.
    #[arg(long)]
    wait: bool,
    /// With --wait: how long to wait.
    #[arg(long, default_value = "60m", value_name = "DURATION")]
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
            } else if e.downcast_ref::<vault::AmbiguousVault>().is_some() {
                EXIT_USAGE
            } else if let Some(d) = e.downcast_ref::<DaemonError>() {
                match d.code {
                    ErrorCode::Locked => EXIT_LOCKED,
                    ErrorCode::NotFound => EXIT_NOT_FOUND,
                    ErrorCode::Invalid => EXIT_USAGE,
                    ErrorCode::Internal | ErrorCode::Declined => EXIT_ERROR,
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
    let vault_arg = cli.file.as_deref();
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
            let name = match name {
                Some(n) => {
                    vault::validate_vault_name(&n).map_err(|e| exit(EXIT_USAGE, e.to_string()))?
                }
                None if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() => {
                    dialoguer::Input::<String>::with_theme(
                        &dialoguer::theme::ColorfulTheme::default(),
                    )
                    .with_prompt("Vault name")
                    .default(vault::default_name(&path))
                    .validate_with(|n: &String| {
                        vault::validate_vault_name(n)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    })
                    .interact_text()?
                }
                None => vault::default_name(&path),
            };
            eprintln!("Creating vault \"{name}\" at {}", path.display());
            let name = Some(name);
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
            .map(|_| EXIT_OK)
        }
        Command::Passkey(PasskeyCommand::Add { label, browser }) => {
            let v = locate(vault_arg)?;
            let client = Client::existing().ok_or_else(|| locked(&v))?;
            let resp = client.request(&Request::Enroll {
                vault_path: v.path.clone(),
                label,
            })?;
            browser_flow(&client, resp, &browser, "register an additional passkey").map(|_| EXIT_OK)
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
        Command::Edit { browser } => {
            let v = locate(vault_arg)?;
            let client = Client::connect_or_spawn()?;
            let resp = client.request(&Request::Edit {
                vault_path: v.path.clone(),
            })?;
            browser_flow(
                &client,
                resp,
                &browser,
                "edit the secrets (confirm with your passkey)",
            )
            .map(|_| EXIT_OK)
        }
        Command::Request {
            key,
            description,
            reason,
            browser,
        } => {
            vault::validate_key_name(&key).map_err(|e| exit(EXIT_USAGE, e.to_string()))?;
            let v = locate(vault_arg)?;
            let client = Client::connect_or_spawn()?;
            let resp = client.request(&Request::RequestSecret {
                vault_path: v.path.clone(),
                key,
                description,
                reason,
            })?;
            let detail = browser_flow(&client, resp, &browser, "provide the secret")?;
            if let Some(final_key) = detail {
                println!("{final_key}");
            }
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
        Command::Wait {
            timeout,
            flow: Some(flow_id),
        } => {
            let client = Client::existing().ok_or_else(|| {
                exit(
                    EXIT_NOT_FOUND,
                    "no agentpass daemon is running, so that flow is gone",
                )
            })?;
            let timeout = parse_duration(&timeout)?;
            if let Some(detail) = wait_flow(&client, &flow_id, timeout)? {
                println!("{detail}");
            }
            Ok(EXIT_OK)
        }
        Command::Wait {
            timeout,
            flow: None,
        } => {
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
                // `-e production/DB_PASSWORD` exports DB_PASSWORD.
                let (name, key) = spec
                    .split_once('=')
                    .unwrap_or((spec.rsplit('/').next().unwrap_or(spec), spec));
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
        Command::Name { new_name } => {
            let mut v = locate(vault_arg)?;
            match new_name {
                None => println!("{}", v.name()),
                Some(n) => {
                    v.file.name = vault::validate_vault_name(&n)
                        .map_err(|e| exit(EXIT_USAGE, e.to_string()))?;
                    v.save()?;
                    eprintln!("Renamed vault to \"{}\"", v.file.name);
                }
            }
            Ok(EXIT_OK)
        }
        Command::Skill => {
            print!("{}", crate::skill::SKILL_MD);
            Ok(EXIT_OK)
        }
        Command::InitSkill {
            tools,
            all,
            global,
            project,
            yes,
        } => {
            use crate::skill::Scope;
            crate::skill::init(crate::skill::InitOptions {
                tools,
                all,
                scope: if global {
                    Some(Scope::Global)
                } else if project {
                    Some(Scope::Project)
                } else {
                    None
                },
                yes,
            })?;
            Ok(EXIT_OK)
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

/// Prints the link, then waits for the browser step. Returns the flow's
/// detail (e.g. the final name of a requested secret).
fn browser_flow(
    client: &Client,
    resp: Response,
    browser: &BrowserArgs,
    what: &str,
) -> Result<Option<String>> {
    let Response::FlowStarted { flow_id, url } = resp else {
        bail!("unexpected daemon response");
    };
    let timeout = parse_duration(&browser.timeout)?;
    eprintln!("Open this link in a browser to {what}:");
    println!("{url}");
    if browser.open {
        open_browser(&url);
    }
    if !browser.wait {
        eprintln!("flow: {flow_id}");
        eprintln!("Then run `agentpass wait {flow_id}` to block until it is done.");
        return Ok(None);
    }
    eprintln!("Waiting for the browser…");
    wait_flow(client, &flow_id, timeout)
}

/// Polls a browser flow until it finishes. Returns its detail.
fn wait_flow(client: &Client, flow_id: &str, timeout: Duration) -> Result<Option<String>> {
    let deadline = (!timeout.is_zero()).then(|| Instant::now() + timeout);
    loop {
        match client.request(&Request::FlowStatus {
            flow_id: flow_id.to_owned(),
        })? {
            Response::FlowState {
                state: FlowState::Done { message, detail },
            } => {
                eprintln!("{message}");
                return Ok(detail);
            }
            Response::FlowState {
                state: FlowState::Failed { message },
            } => bail!("{message}"),
            Response::FlowState {
                state: FlowState::Expired,
            } => return Err(exit(EXIT_TIMEOUT, "the link expired")),
            _ => {}
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(exit(EXIT_TIMEOUT, "timed out waiting for the browser"));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}
