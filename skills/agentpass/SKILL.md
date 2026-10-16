---
name: agentpass
description: Use secrets (API keys, tokens, passwords, credentials such as GITHUB_TOKEN, NPM_TOKEN or a database password) stored in an agentpass vault (*.agentpass.toml) without exposing them. Use when a command needs a credential, when a task mentions agentpass or a *.agentpass.toml file, when a command fails for missing or invalid credentials and a vault exists, or when the user asks to store a new secret.
---

# agentpass: using secrets safely

agentpass keeps secrets in a `*.agentpass.toml` vault (default `secrets.agentpass.toml`). Names and descriptions are plain text; values are encrypted. The user unlocks the vault with a passkey in their browser, and only then can the `agentpass` CLI hand out values.

## Rules

1. **Never put a secret value into your context.** Don't print it, echo it, `cat` it, log it, write it to a file or capture `agentpass get` output into a variable you read. Pass it straight to the command that needs it:
   - pipe it: `agentpass get KEY | some-command --password-stdin`
   - or put it in a child process's environment: `agentpass run -e KEY -- some-command args`
2. **Never run `agentpass get --reveal`**, and never decrypt or edit the vault file by hand.
3. **Don't ask the user to paste secrets into the chat.** To store a new secret, ask them to run `agentpass set KEY -d "description"` in their own terminal. It prompts without echoing.
4. **Only the user unlocks.** You can request an unlock and wait for it; the user chooses how long it stays unlocked.

## Workflow

```sh
agentpass list                      # which secrets exist (names + descriptions; works while locked)
agentpass status                    # exit 0 = unlocked, 3 = locked
```

If the vault is locked (any command exits with code **3**):

```sh
agentpass unlock --suggest 1h       # prints a link; returns immediately
```

Show the user the printed `http://localhost:…` link and ask them to open it and confirm with their passkey. Suggest a duration that fits the task (`30m`, `1h`, `8h`, or `forever`). Then block until they're done:

```sh
agentpass wait --timeout 10m        # exit 0 = unlocked, 5 = timed out
```

Then use the secret:

```sh
agentpass get GITHUB_TOKEN | gh auth login --with-token
agentpass run -e PGPASSWORD=DB_PASSWORD -- psql -h db -U app -c 'select 1'
agentpass run -e NPM_TOKEN -e GH=GITHUB_TOKEN -- npm publish
```

`run -e NAME=KEY` exports secret `KEY` as environment variable `NAME`; `-e KEY` uses the same name. `run` exits with the command's own exit code.

When you are finished with work that needed secrets, run `agentpass lock` unless the user asked to keep the vault unlocked.

## Folders

Secret names can contain folders, e.g. `production/DB_PASSWORD` and `testing/DB_PASSWORD`. `agentpass list` shows full names. `agentpass run -e production/DB_PASSWORD -- cmd` exports it as `DB_PASSWORD`; use `-e NAME=production/DB_PASSWORD` for another variable name. Pick the folder that matches the environment the user asked for.

## Several vaults

agentpass uses the `*.agentpass.toml` in the current directory (or the nearest parent that has one). If a directory has several, commands exit with code **2** and list them. Then add `--file <path>` (relative to the current directory) to every command, e.g. `agentpass --file prod.agentpass.toml get API_KEY`. If it is unclear which vault the task needs, ask the user.

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | ok | |
| 1 | error | read the message |
| 2 | usage error, or several vaults found | fix the command; for several vaults add `--file <path>` |
| 3 | vault locked | `agentpass unlock`, give the user the link, `agentpass wait` |
| 4 | secret or passkey not found | `agentpass list`; ask the user to `agentpass set` it |
| 5 | timed out | ask the user whether they still want to unlock, then retry |

## Setting up a new vault

Only if the user asks for it: `agentpass setup --name "<project>"` prints a link where the user registers a passkey (a security key, or a passkey in their browser or password manager that supports PRF). It creates `secrets.agentpass.toml`, which is safe to commit.
