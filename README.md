# asiri

let agents use secrets without seeing them.

*àṣírí* is Yoruba for "secret". An agent asks for `asiri://dev/github`, you approve, and asiri hands the value to the command that needs it. The agent gets the result, never the secret.

> **status: v0.1 in progress.** Works: the encrypted vault in a container, pairing over mTLS, `asiri add` / `ls`, and `asiri run` with approvals in the terminal, an allow-list of programs, and secrets scrubbed from output. Next: Rex approvals, SSH, the MCP server. See [ARCHITECTURE.md](ARCHITECTURE.md).

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

## 04 let a program use it

```sh
asiri policy dev/github --bins gh --max-grant 1h     # only gh may receive it
asiri run --env GH_TOKEN=asiri://dev/github --reason "open the PR" -- gh pr create --fill
```

You're asked once (Return = once, `f` = 15 min, `h` = 1 hour, `d` = deny). Within a 15 min or 1 h grant, the same program runs again without asking.

When an agent runs it (no terminal), it waits and prints the command to approve it in yours:

```text
asiri: claude wants asiri://dev/github
asiri:   gh pr create --fill · ~/proj/api · "open the PR"
asiri: waiting for approval (until 17:07:42). in your terminal, run:

  asiri approve 01M7WV9QAXVYMTM68PR5WQA8SW
```

| delivery | how | note |
|---|---|---|
| `--stdin REF` | written to the program's stdin | best when the program reads it (`docker login --password-stdin`) |
| `--file NAME=REF` | a one-time pipe; `NAME` is its path | never on disk; readable once |
| `--env NAME=REF` | an environment variable | easiest; other processes running as you can read it (`ps eww`) while it runs |

What asiri won't do:

- give a secret to a shell, interpreter or wrapper (`sh`, `python`, `node`, `env`, `xargs`, `sudo`, ...): they could print or send it anywhere. Exit `126`.
- give it to a program not in the item's `--bins`. Exit `126`.
- let the value reach you or the agent in the output: it, and its base64, hex and URL forms, become `[asiri:asiri://dev/github]`, and the audit log records a `scrub_hit`.

Scrubbing is a safety net, not the defence: an allowed program with its own way to send data out (`gh gist create`) can still do that. Pick `--bins` with that in mind.

## give an agent its own profile

```sh
asiri clients add claude             # prints a code
asiri pair --profile claude --code <code>
ASIRI_PROFILE=claude asiri ls        # agents can list; they can't add, unlock or read the log
```

## everything else

| command | does |
|---|---|
| `asiri approve [ID] [--for 15m]` / `asiri deny ID` | answer waiting requests |
| `asiri grants` / `asiri revoke ID` / `asiri revoke --all` | live grants / revoke one / kill switch |
| `asiri lock` / `asiri unlock` | lock now / unlock (passphrase, or the server's key file) |
| `asiri clients ls` / `revoke NAME` | see and revoke paired clients |
| `asiri log` / `asiri log verify` | read the audit log / check its hash chain |
| `asiri server init/run/keygen/pair-code/health` | server side, usually inside the container |

Exit codes, as in `docker run`: `125` asiri failed, `126` refused, denied or expired, `127` program not found, `2` usage; otherwise `asiri run` exits with the program's own code.

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
