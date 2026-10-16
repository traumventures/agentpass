---
name: agentpass
description: Use secrets (API keys, tokens, passwords, credentials such as GITHUB_TOKEN, NPM_TOKEN or a database password) stored in an agentpass vault (*.agentpass.toml) without exposing them, and ask the user for new secrets. Use when a command needs a credential, when a task mentions agentpass or a *.agentpass.toml file, when a command fails for missing or invalid credentials and a vault exists, or when a secret has to be added or changed.
---

# agentpass: using secrets safely

agentpass keeps secrets in a `*.agentpass.toml` vault (default `secrets.agentpass.toml`). Names, folders and descriptions are plain text; values are encrypted. The user unlocks the vault with a passkey in their browser; only then can the `agentpass` CLI hand out values.

## Rules

1. **Never put a secret value into your context.** Don't print, echo, `cat`, log or write it to a file, and don't capture `agentpass get` output into something you read. Pass it straight to the command that needs it:
   - pipe it: `agentpass get KEY | some-command --password-stdin`
   - or as a child process's environment: `agentpass run -e KEY -- some-command args`
2. **Secrets are only ever added or changed in the browser.** There is no CLI command for it, and you must not create another way:
   - never ask the user to paste a secret into the chat, a terminal, a file, an env var or a script;
   - never write values into the vault file, `.env` files or anything else yourself;
   - if the user offers to paste a secret here, decline and use `agentpass request` instead.
3. **Never run `agentpass get --reveal`** and never edit the vault file by hand.
4. **Only the user unlocks.** You request an unlock and wait; the user chooses how long it stays unlocked.

## Reading secrets

```sh
agentpass list                      # names (with folders) + descriptions; works while locked
agentpass status                    # exit 0 = unlocked, 3 = locked
```

If the vault is locked (any command exits with code **3**), follow the browser-step pattern below with `agentpass unlock --suggest 1h` (suggest `30m`, `1h`, `8h` or `forever` to fit the task; the user decides).

Then use the secret:

```sh
agentpass get GITHUB_TOKEN | gh auth login --with-token
agentpass run -e PGPASSWORD=production/DB_PASSWORD -- psql -h db -U app -c 'select 1'
agentpass run -e NPM_TOKEN -- npm publish
```

`run -e NAME=KEY` exports secret `KEY` as variable `NAME`; `-e production/DB_PASSWORD` exports `DB_PASSWORD`. `run` exits with the command's own exit code. When done, run `agentpass lock` unless the user wants it to stay unlocked.

## Asking for a new secret

```sh
agentpass request production/STRIPE_KEY -d "Stripe live secret key" --reason "deploy needs to charge cards"
```

Use the browser-step pattern above. On the page the user sees the vault's tree with your suggestion, can change the folder, name and description, and type the value. Then `agentpass wait <ID>` blocks until they save (exit 0) or decline (exit 1) and prints the **final name**. Use that name, it may differ from your suggestion. Pick folders that match the existing tree (`agentpass list`), e.g. `production/` vs `testing/`.

For bigger changes (renaming, deleting, reorganising folders), suggest `agentpass edit`: it opens the user's passkey-protected editor.

## Browser steps: start, show the link, then wait

`unlock`, `setup`, `request`, `edit` and `passkey add` need the user in the browser. They print a link on stdout and `flow: <ID>` on stderr, then return at once. Always do exactly these three steps, in this order:

1. **Start:** run the command on its own, e.g. `agentpass unlock --suggest 1h`. Never chain `wait` onto it (`… && agentpass wait`, `;`, pipes, background jobs).
2. **Show:** send the user a message with the full `http://localhost:…#…` link (and what to do there) **before** running anything else. The user cannot see command output that you don't relay, and a blocked command can't show them anything.
3. **Wait:** run `agentpass wait <ID>` as a separate command. It blocks until the user is done and prints the result (for `request`: the final secret name). Exit 5 = timed out: ask the user, then wait again or start a new link.

```sh
agentpass request production/STRIPE_KEY -d "Stripe key"   # 1. stdout: link, stderr: "flow: <ID>"
# 2. message to the user: "Please open <link> and enter the Stripe key."
agentpass wait <ID>                                        # 3. prints production/STRIPE_KEY
```

## Folders and several vaults

Secret names may contain folders: `production/DB_PASSWORD`, `testing/DB_PASSWORD`. Choose the folder matching the environment the user asked for.

agentpass uses the `*.agentpass.toml` in the current directory (or the nearest parent that has one). If a directory has several, commands exit with code **2** and list them; then add `--file <path>` (relative to the current directory) to every command. If it's unclear which vault the task needs, ask the user.

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | ok | |
| 1 | error, or the user declined a request | read the message |
| 2 | usage error, or several vaults found | fix the command; for several vaults add `--file <path>` |
| 3 | vault locked | `agentpass unlock`, show the user the link, then `agentpass wait <ID>` |
| 4 | secret not found | `agentpass list`; if it's missing, `agentpass request` it |
| 5 | timed out | ask the user whether to continue, then retry |

## Setting up a new vault

Only when the user asks: `agentpass setup --name "<project>"` prints a link (then `agentpass wait <ID>`) where the user registers a passkey (security key, or a passkey in their browser/password manager with PRF support). It creates `secrets.agentpass.toml`, which is safe to commit.
