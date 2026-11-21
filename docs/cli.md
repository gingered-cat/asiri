# cli usage

Use references instead of values. A reference such as `asiri://dev/github` identifies a secret without revealing it.

## profiles and permissions

An owner can store secrets, set policy, and approve requests. An agent can list secret metadata and request permitted use.

Select a profile with `--profile NAME` on the command or `ASIRI_PROFILE=NAME` in its environment. Without either, the CLI uses `owner`.

```sh
asiri status
asiri ls
ASIRI_PROFILE=claude asiri ls
```

## store and allow

```sh
asiri add dev/github
asiri policy dev/github --bins gh --max-grant 1h
```

The add prompt hides what you type. `--bins` lists the programs allowed to receive the secret. `--max-grant` limits approvals to `once`, `15m`, or `1h`.

### environment variables

```sh
asiri run --env GH_TOKEN=asiri://dev/github \
  --reason "open the PR" -- gh pr create --fill
```

The variable is set for the child program. Other processes running as your user can inspect its environment while it runs. Prefer stdin when the program supports it.

### stdin and files

Replace `YOUR_USER` with your registry username:

```sh
asiri run --stdin asiri://dev/registry \
  --reason "sign in to the registry" -- docker login ghcr.io \
  --username YOUR_USER --password-stdin
```

For a program that reads a file path from an environment variable, use a one-time pipe:

```sh
asiri run --file KUBECONFIG=asiri://ops/kubeconfig \
  --reason "check the rollout" -- kubectl get pods
```

The pipe is readable once and does not store the value on disk. The program must support that access pattern. `--env` and `--file` can be repeated.

Put asiri flags before `--`. Everything after it is the actual program and its arguments. Shells, interpreters, and wrappers are refused.

## requests and grants

```sh
asiri pending
asiri approve ID --for 15m
asiri deny ID
asiri grants
asiri revoke ID
asiri revoke --all
```

Use a request ID with `approve` or `deny`. Use a grant ID with `revoke`. A grant lets the same program reuse an approved secret until expiry or revocation.

`revoke --all` also denies pending requests. It cannot take back a value already delivered to a process.

## ssh keys

First connect to your SSH host normally and verify its host key. Then generate an asiri key bound to that host:

```sh
asiri add ops/staging --ssh-generate --ssh-hosts staging
asiri pubkey ops/staging
```

Install the public key in the remote account's `~/.ssh/authorized_keys`. Do not copy a private key out of the vault.

```sh
asiri ssh --reason "check staging" staging hostname
```

Put asiri's `--reason` before the destination. The remaining arguments go to OpenSSH. This needs OpenSSH 8.9 or newer for host-bound signing. Agent forwarding and non-login signatures are refused.

## import passwords

Export from Apple Passwords or Google Password Manager yourself. Keep the plaintext export outside cloud-synced folders.

```sh
asiri import ~/Downloads/Passwords.csv --dry-run
asiri import ~/Downloads/Passwords.csv
```

The second command overwrites and deletes the export after importing it. `--keep` preserves it. SSDs, snapshots, and backups can retain deleted data. Remove other copies and use disk encryption.

Imported secrets are not usable until you set their allowed programs. Run `asiri ls` to find the exact references before setting policy.

## lock and audit

```sh
asiri lock
asiri unlock
asiri log
asiri log verify
```

The audit log is hash-chained. Verification checks its chain, not whether every action was a good decision. Only an owner can read it.

## install and update

```sh
curl -fsSL https://asiri.run/install.sh | sh   # first install: latest release, checksum-verified
asiri update --check                           # is a newer release out?
asiri update                                   # replace this binary with it
```

`asiri update` downloads the release for your OS and chip, checks it against the release's `checksums.txt`, and swaps it in place of the running binary. If the Rex plugin uses this binary, it reinstalls the plugin from the new version. The server is a separate process: update its container with `docker compose -f deploy/compose.yaml pull` and `up -d`. A development build refuses to replace itself unless you pass `--force`; so does an older `--version`. `v0.1.0` predates `asiri update`, so run the install script once to get it.

## exit codes

| code | meaning |
| --- | --- |
| 125 | asiri itself failed. |
| 126 | Refused, denied, or expired. Do not work around a denial. |
| 127 | The program was not found. |
| 2 | The command has a usage error. |
| other | The child program's exit code. |

An allowed program can still send a credential elsewhere. Scrubbing covers the value and known base64, hex, and URL representations, not arbitrary encodings. Choose allowed programs with that limit in mind.
