---
name: asiri
description: Use secrets (API tokens, passwords, SSH keys) through asiri without seeing them. Use whenever a command needs a credential.
---

# asiri

asiri keeps secrets in a vault you can't read. When a command needs one, you ask asiri to run that command with the secret delivered to it. A person approves the request. You get the command's output, with the secret scrubbed out of it. You never get the value.

## Rules

- Never ask the user to paste a secret into the chat, and never read one from a file, env var or keychain yourself. Ask through asiri.
- Never try to print, echo, decode or send a secret anywhere. asiri scrubs it from output and logs a `scrub_hit` when that happens.
- Give every request a short, honest `--reason`. The person approving sees it.
- Run the real program directly. asiri refuses shells, interpreters and wrappers (`sh`, `bash`, `python`, `node`, `env`, `xargs`, `sudo`, ...).

## Check that asiri is set up

```sh
asiri status      # paired? server reachable? vault unlocked?
asiri ls          # names, kinds and versions of secrets; never values
```

If `asiri` isn't installed or isn't paired, stop and tell the user. Setup is theirs to do: https://asiri.run

## Use a secret

Secrets are named by reference, such as `asiri://dev/github`. Pick a delivery:

```sh
# as an environment variable (easiest)
asiri run --env GH_TOKEN=asiri://dev/github --reason "open the PR" -- gh pr create --fill

# on the program's stdin (best when the program reads it)
asiri run --stdin asiri://dev/registry --reason "push the image" -- docker login ghcr.io -u me --password-stdin

# as a one-time pipe; NAME holds its path, readable once
asiri run --file KUBECONFIG=asiri://ops/kubeconfig --reason "check the rollout" -- kubectl get pods
```

`--env` and `--file` can be repeated. Everything after `--` is the program and its arguments.

The command waits until the person answers. They may allow it once, for 15 minutes or for 1 hour. Within a 15-minute or 1-hour grant, the same program runs again without asking. If no approval app is open, asiri prints an `asiri approve <ID>` command: show it to the user and wait.

## SSH

The private key never leaves the asiri server, and it only signs in to the hosts the user allowed.

```sh
asiri ssh --reason "deploy" staging -- ./deploy.sh
```

Put `--reason` before the host; everything after it goes to `ssh`.

## Exit codes

| code | meaning | what to do |
|---|---|---|
| `126` | refused, denied or expired | tell the user; don't retry another way |
| `125` | asiri itself failed | show the error to the user |
| `127` | program not found | check the program name |
| `2` | usage error | fix the command |
| other | the program's own exit code | handle it as usual |

A `126` is an answer, not an obstacle: the person said no, the program isn't allowed to receive that secret, or the program is a shell. Don't work around it.
