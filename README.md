# agentpass

**A password manager for AI agents, unlocked with your passkey.**

Your agent needs a GitHub token, an API key or a database password. With agentpass:

- Secrets live in an `agentpass.toml` file you can commit to git. Names and descriptions are plain text; **only the values are encrypted**.
- When the agent needs a secret, it asks you to unlock the vault. You open a link on `localhost`, **choose how long it stays unlocked** (15 min … 24 h, custom, or until locked) and confirm with a **passkey**: a security key such as a YubiKey, or a passkey from a password manager in your browser.
- Decrypted data **exists only in RAM**, inside a small background daemon. The agent gets values **through a pipe** or **as environment variables of a child process**, never through files.

```sh
agentpass get GITHUB_TOKEN | gh auth login --with-token
agentpass run -e NPM_TOKEN -- npm publish
```

Linux and macOS are supported.

## Install

Download a binary from the [releases](https://github.com/traumventures/agentpass/releases), or build it yourself:

```sh
rustup target add wasm32-unknown-unknown
cargo install trunk just
git clone https://github.com/traumventures/agentpass && cd agentpass
just install          # builds the Yew web UI, then installs the binary
```

## Quick start

```sh
cd my-project
agentpass setup --open                 # create agentpass.toml, register a passkey
agentpass set GITHUB_TOKEN -d "PAT for CI"   # prompts without echo (or pipe the value in)
git add agentpass.toml && git commit -m "Add agentpass vault"

agentpass unlock --open                # pick a duration, touch your passkey
agentpass get GITHUB_TOKEN | gh auth login --with-token
agentpass lock
```

`set`, `list` and `rm` work while the vault is locked: values are encrypted to the vault's public key, so adding a secret never needs the passkey.

## Commands

| Command | What it does |
|---|---|
| `agentpass setup [--name N] [--label L] [--open]` | Create a vault and register its first passkey in the browser |
| `agentpass passkey add [--label L] [--open]` | Register a backup passkey (vault must be unlocked) |
| `agentpass passkey list` / `remove <label\|id>` | List or remove passkeys (`remove` needs the vault unlocked; the last passkey cannot be removed) |
| `agentpass set KEY [-d DESC] [--raw]` | Encrypt and store a value from stdin or a hidden prompt |
| `agentpass list [--json]` / `rm KEY` | Show names and descriptions / delete a secret |
| `agentpass unlock [--suggest 1h\|forever] [--open] [--force]` | Print an unlock link and return immediately |
| `agentpass wait [--timeout 10m]` | Block until the vault is unlocked (`--timeout 0` waits forever) |
| `agentpass get KEY [--reveal]` | Write the value to stdout for piping (refuses a terminal unless `--reveal`) |
| `agentpass run -e KEY -e NAME=KEY -- cmd args…` | Run `cmd` with secrets as environment variables |
| `agentpass lock [--all]` | Lock now; the key is wiped from memory |
| `agentpass status [--all] [--json]` | Show lock state and time left |

The vault is the `--vault` path, then `$AGENTPASS_VAULT`, then the nearest `agentpass.toml` in the current directory or its parents.

**Exit codes:** `0` ok · `1` error · `2` usage · `3` locked · `4` not found · `5` timeout. `status` exits `3` when locked.

## For agents

Paste this into your `AGENTS.md` / `CLAUDE.md`:

```markdown
## Secrets (agentpass)
- Secrets are in agentpass.toml. List them with `agentpass list`.
- Never print a secret or capture it into your context. Pipe it into the command
  that needs it (`agentpass get KEY | cmd --password-stdin`) or use
  `agentpass run -e KEY -- cmd`.
- If a command exits with code 3, the vault is locked: run `agentpass unlock`,
  show the user the printed link, then run `agentpass wait` and retry.
- Do not run `agentpass get --reveal`.
```

## How it works

```text
   agent ──CLI──▶ agentpass ──Unix socket (0600, same uid)──▶ daemon (keys in mlocked RAM)
                                                              │
   user  ──browser──▶ http://localhost:47117 (Yew UI) ────────┘  WebAuthn PRF ▶ unwrap vault key
```

### Vault file

```toml
version = 1
vault_id = "01JA…"
name = "my-project"
public_key = "base64…"                 # X25519

[[passkeys]]
label = "YubiKey 5C"
credential_id = "base64url…"
prf_salt = "base64url…"
wrapped_private_key = "apw1:…"         # private key, encrypted with this passkey's PRF output

[secrets.GITHUB_TOKEN]
description = "PAT for CI"
value = "ap1:…"                        # encrypted to public_key
```

### Cryptography

- **Passkey to key.** The WebAuthn **PRF extension** (CTAP2 `hmac-secret`) returns a stable 32-byte secret per passkey and salt. agentpass derives a wrapping key from it with HKDF-SHA256 and unwraps the vault's X25519 private key (XChaCha20-Poly1305). The unwrapped key must match `public_key`, so a successful unlock proves the passkey is genuine. Passkeys without PRF are refused at setup. User verification is always required, because CTAP2 returns different PRF outputs with and without it.
- **Values** are sealed to the vault's public key: ephemeral X25519, HKDF-SHA256, then ChaCha20-Poly1305. The vault id and secret name are authenticated, so a ciphertext cannot be moved to another key or vault.
- **Several passkeys.** Each enrolled passkey wraps the same private key, so a backup passkey can unlock the vault on its own.

### Protecting secrets in RAM

1. **Little plaintext, kept briefly.** Only the 32-byte vault private key stays decrypted. Each `get`/`run` decrypts one value, sends it and wipes it; nothing is cached.
2. **No swap, no dumps.** Keys and values live in dedicated `mmap` regions with guard pages, locked with `mlock` and marked `MADV_DONTDUMP` (plus `MADV_WIPEONFORK`). The daemon sets `RLIMIT_CORE=0`.
3. **No same-user inspection.** On Linux the daemon is `PR_SET_DUMPABLE=0`, so ptrace and `/proc/<pid>/mem` are denied to other processes of the same user. On macOS it uses `PT_DENY_ATTACH`.
4. **Reliable wiping.** Buffers are wiped with `zeroize` on drop. They have a fixed size, so no reallocation leaves copies behind. Secret types print as `[REDACTED]`, and the daemon never logs secrets.
5. **Few copies.** Values are decrypted in place into locked memory and written to the socket from there. The CLI reads them into locked memory. `run` uses `execve` directly, with no shell and no temp files.
6. **Locking.** The key is wiped when the chosen time is up, on `agentpass lock`, on SIGTERM/SIGINT/SIGHUP, **before the system sleeps** (logind `PrepareForSleep` on Linux, IOKit power notifications on macOS, plus a clock check that catches any missed suspend) and **when your login session ends**. "Until locked" still ends on sleep, logout or reboot.
7. **Access control.** The socket sits in a `0700` directory (`$XDG_RUNTIME_DIR/agentpass`) with mode `0600`, and the daemon checks the peer uid on every connection. The web server listens only on `127.0.0.1`. It rejects foreign `Host` headers (DNS rebinding) and cross-origin POSTs, and sends a strict CSP. Each link carries a one-time token in the URL fragment; the token expires after 15 minutes or 5 failed attempts and is removed from the address bar on load.

These are tested: [`crates/agentpass/tests/memory.rs`](crates/agentpass/tests/memory.rs) checks that ptrace and `/proc/<pid>/mem` are denied and that the daemon writes no core dump. Run as root (`just test-memory`), it also scans the daemon's memory to confirm the key is present only in one mlocked, no-dump mapping, that served plaintext doesn't linger, and that the key bytes are gone after `lock`.

### Limits (threat model)

- **While unlocked, any process running as your user can ask the daemon for secrets.** That is what lets your agent use them. Unlock for short periods and lock when done.
- **Root and the kernel can read any memory.**
- **Once a value has been piped into another program, protecting it is up to that program.**
- **Leaked values.** If an agent captures `agentpass get` output into its own context instead of piping it, the value ends up in the agent's transcript. Use the patterns above.
- **Remote machines.** The unlock page uses the `localhost` relying party. If agentpass runs on a remote machine, forward the port (`ssh -L 47117:localhost:47117 host`) and open the link locally. Set `AGENTPASS_PORT` to change the port.

## Passkey support

PRF is supported by current Chrome, Edge, Safari and Firefox, FIDO2 security keys with `hmac-secret` (YubiKey 5, SoloKeys, Nitrokey 3, Google Titan …), iCloud Keychain, Google Password Manager, 1Password and Bitwarden. If a passkey can't do PRF, setup says so and nothing is saved.

## Environment

| Variable | Purpose |
|---|---|
| `AGENTPASS_VAULT` | Vault path (like `--vault`) |
| `AGENTPASS_PORT` | Web UI port (default `47117`; `0` = random) |
| `AGENTPASS_RUNTIME_DIR` | Socket, lock file and daemon log directory |
| `AGENTPASS_IDLE_EXIT_SECS` | Daemon exits after this long with nothing unlocked (default 1800, `0` = never) |

## Development

```sh
just web          # build the Yew UI (crates/web) with trunk
just build        # release binary with the UI embedded
just test         # unit + integration tests, then Playwright e2e in Chromium with a virtual PRF authenticator
just test-memory  # memory scans (needs sudo)
just lint
```

Layout: `crates/agentpass` (CLI, daemon, crypto, vault, locked memory, web server), `crates/protocol` (types shared with the UI), `crates/web` (Yew UI), `e2e` (Playwright).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
