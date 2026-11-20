# asiri

let agents use secrets without seeing them.

*àṣírí* is Yoruba for "secret". An agent asks for `asiri://dev/github`, you approve, and asiri hands the value to the command that needs it. The agent gets the result, never the secret.

> **status: v0.1 in progress.** Milestone 1 works: an encrypted vault in a container, pairing over mTLS, `asiri add`, `asiri ls`, lock/unlock, and a tamper-evident audit log. `asiri run`, Rex approvals, SSH and the MCP server come next. See [ARCHITECTURE.md](ARCHITECTURE.md).

## 01 run the server

```sh
go run ./dev bin && export PATH="$PWD/bin:$PATH"             # from a clone; go install once published
asiri server keygen -o ~/.config/asiri/master.key            # back this file up
cd deploy && docker compose up -d
```

The server listens on `127.0.0.1:7420` only. On first start it creates the vault from the key file.

On Linux Docker, the container runs as uid 65532 and must be able to read the key file: `sudo chown 65532 ~/.config/asiri/master.key`. Docker Desktop and OrbStack on macOS handle this for you.

Prefer a passphrase you type at each start? `docker compose run --rm -it asiri server init --passphrase`, remove the `secrets:` lines from `compose.yaml`, then `asiri unlock` after each start.

## 02 pair this machine

```sh
docker compose exec asiri asiri server pair-code
asiri pair --code <code>
asiri status
```

The code carries the server's CA fingerprint, so `asiri pair` refuses a server that doesn't match before sending anything. Codes work once, for 10 minutes.

## 03 store and list

```sh
asiri add dev/github                 # typed without echo
gh auth token | asiri add dev/github --stdin
asiri ls                             # names, kinds, versions; never values
```

## give an agent its own profile

```sh
asiri clients add claude             # prints a code
asiri pair --profile claude --code <code>
ASIRI_PROFILE=claude asiri ls        # agents can list; they can't add, unlock or read the log
```

## everything else

| command | does |
|---|---|
| `asiri lock` / `asiri unlock` | lock now / unlock (passphrase, or the server's key file) |
| `asiri clients ls` / `revoke NAME` | see and revoke paired clients |
| `asiri log` / `asiri log verify` | read the audit log / check its hash chain |
| `asiri server init/run/keygen/pair-code/health` | server side, usually inside the container |

Exit codes: `125` asiri failed, `2` usage; `126`/`127` are kept for `asiri run`.

## how it's built

- one Go binary: `asiri server` in the container, the same binary as the CLI on the host
- vault: SQLite; key file or Argon2id passphrase → KEK → vault key → per-version data key → XChaCha20-Poly1305 with the item id, version and field bound in
- transport: TLS 1.3, client certificates, CA pinned at pairing; roles `owner` and `agent`
- audit: hash-chained, written in the same transaction as the change it records

## develop

```sh
go run ./dev ci      # fmt, vet, test -race, cross-compile
go run ./dev image   # docker build
```

## license

Apache-2.0
