---
name: asiri
description: Use secrets (API tokens, passwords, SSH keys, database URLs) without seeing them, through asiri. Use whenever a task needs a credential, a login, an API key or token, an SSH key, sudo or a database password, or when the person mentions asiri, a secret, or `asiri://` references. Never ask for a secret in the chat.
---

# asiri: use secrets without seeing them

asiri keeps the person's secrets. You ask for one by reference (`asiri://vault/name[/field]`), the person approves in Rex or their terminal, and asiri hands the secret straight to the program that needs it. You get the program's result, with the secret replaced by `[asiri:REF]`. You never see the value, and you don't need to.

## Rules

1. **Never ask the person to paste a secret into the chat**, and never type, echo, print, log or write one to a file. If you need a secret, use a reference.
2. **Find secrets** with the `list_secrets` tool (or `asiri ls`). It shows each reference and the programs or SSH hosts it may be used with.
3. **Use secrets** with `run_with_secrets` / `ssh_run` (or `asiri run` / `asiri ssh`). Always give a short, honest `reason`; the person reads it before approving.
4. **Prefer `stdin` or `files` over `env`** when the program can read a secret that way (`docker login --password-stdin`, `--password-file`). Environment variables can be read by other processes running as the same user.
5. **Run the real program, not a shell.** asiri refuses shells, interpreters and wrappers (`sh -c`, `bash`, `python`, `node`, `env`, `xargs`, `sudo`, …) because they could print or send the secret anywhere. Call `gh`, `psql`, `terraform`, `curl` directly.
6. **A secret is only for its allowed programs** (`programs` in `list_secrets`). If the one you need isn't allowed, tell the person and suggest `asiri policy REF --bins PROGRAM`. Don't try another program or another secret.
7. **A denied request is final.** Tell the person what you were trying to do; don't retry.
8. **If a secret doesn't exist**, call `request_missing_secret` (or ask the person to run `asiri add REF` in their own terminal). Never collect it yourself.
9. **Put references, not values, in files you write**: `.env.example`, configs, docs and commits get `asiri://dev/github`, never the token.
10. **If output shows `[asiri:…]`**, the program printed a secret and asiri caught it. Don't try to recover it; mention it if it matters.

## Tools (MCP: `asiri mcp`)

| Tool | Use it to |
|---|---|
| `list_secrets(query?)` | see references, kinds, allowed programs and SSH hosts |
| `run_with_secrets(command[], env?, stdin?, files?, cwd?, reason, timeout_seconds?)` | run one program with secrets delivered; returns exit code, scrubbed stdout/stderr, approval notes |
| `ssh_run(destination, command, ssh_args?, reason)` | run a command over ssh with an asiri key (the key never leaves asiri) |
| `request_missing_secret(ref, reason, wait_seconds?)` | ask the person to add a secret, and wait for it |

Example:

```json
{"command": ["gh", "pr", "create", "--fill"], "env": {"GH_TOKEN": "asiri://dev/github"}, "reason": "open the PR for the login fix"}
```

## Without MCP (shell)

```sh
asiri ls                                                   # references only
asiri run --env GH_TOKEN=asiri://dev/github --reason "open the PR" -- gh pr create --fill
asiri run --stdin asiri://dev/registry --reason "push image" -- docker login ghcr.io -u me --password-stdin
asiri ssh --reason "deploy" -- staging ./deploy.sh
```

When nobody can be asked in Rex, the command waits and prints `asiri approve <ID>`: tell the person to run that in their own terminal. Exit code 126 means refused, denied or expired; 127 means the program wasn't found; anything else is the program's own.
