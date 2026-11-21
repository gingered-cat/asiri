# asiri

let agents use secrets without seeing them.

*àṣírí* is Yoruba for "secret". An agent asks for `asiri://dev/github`, you approve, and asiri hands the value to the command that needs it. The agent gets the result, never the secret.

> **status: v0.1.0.** Encrypted vault, pairing, `asiri run`, Rex approvals, host-bound SSH keys, Apple and Google CSV import, and an MCP server with an agent skill. Binaries and the container image are published from the `v0.1.0` tag. See [ARCHITECTURE.md](ARCHITECTURE.md).

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

## 05 approve from Rex

```sh
asiri rex install
```

asiri joins Rex's command palette, and every request from an agent pops up there, on every Rex app you have connected. The first answer wins. Return allows once; closing the prompt denies.

```text
claude wants asiri://dev/github
  › Allow once                 gh pr create --fill · ~/proj/api · "open the PR"
    Allow for 15 minutes
    Allow for 1 hour
    Deny
```

The plugin records your answer itself, running `asiri approve` with your **owner** profile. The agent that asked can't approve anything: the server refuses decisions from agent profiles.

Also in the palette: **Asiri: Approve Waiting Requests…**, **Asiri: Revoke Everything** (the kill switch) and **Asiri: Lock the Vault**. `asiri rex uninstall` removes it. asiri only touches its own marked block in `init.lua`, and puts the file back if `rex config check` rejects the change. For a Rex server other than the local one, set `ASIRI_REX_SERVER` (a host label or socket path).

Without Rex, or when no Rex app is open, asiri asks in your terminal if you ran the command yourself. When an agent ran it, asiri waits and prints the command for you to approve in your own terminal:

```text
asiri: claude wants asiri://dev/github
asiri:   gh pr create --fill · ~/proj/api · "open the PR"
asiri: waiting for approval (until 17:07:42). in your terminal, run:

  asiri approve 01M7WV9QAXVYMTM68PR5WQA8SW
```

## 06 ssh without handing out the key

```sh
asiri add ops/staging --ssh-generate --ssh-hosts staging    # the key is made inside the server
ssh staging 'cat >> ~/.ssh/authorized_keys' <<< "$(asiri pubkey ops/staging)"
asiri ssh staging -- ./deploy.sh
```

`--ssh-hosts staging` reads staging's host key from your `known_hosts` (after `~/.ssh/config`), so the key can only sign in to that machine. Each login is approved like any other request (Rex, the terminal, or `asiri approve`). The private key never leaves the asiri server: the server signs.

For git, rsync and anything else that uses an agent:

```sh
asiri ssh-agent                              # in its own pane; serves ~/.asiri/agent.sock
export SSH_AUTH_SOCK=~/.asiri/agent.sock     # elsewhere (or IdentityAgent in ~/.ssh/config)
git push
```

asiri's agent refuses: hosts not in `--ssh-hosts` (the key isn't even offered), signing anything that isn't a login to the host ssh is connected to (`ssh-keygen -Y sign`, commit signing), agent forwarding, and `ssh-add`. It needs OpenSSH 8.9 or newer, which tells the agent which host it's signing in to. An existing key can be imported with `asiri add ops/old --kind ssh_key --stdin < ~/.ssh/id_ed25519`; it must not have a passphrase, since asiri now protects it.

## 07 bring your Apple or Google passwords

Neither Apple Passwords nor Google Password Manager lets another app read passwords on demand, so asiri imports their export once and keeps its own encrypted copy.

```sh
# export first: the Passwords app's File menu (export to a file, not to an app),
# or passwords.google.com → Settings → Export passwords
asiri import ~/Downloads/Passwords.csv --dry-run      # what would be imported (names only)
asiri import ~/Downloads/Passwords.csv                # stores it, then overwrites and deletes the file
```

The format is detected from the header (Apple: `Title,URL,Username,Password,Notes,OTPAuth`; Google: `name,url,username,password,note`). Each login becomes `asiri://apple/<site>/password`, plus `/username`, `/url`, `/totp` and `/notes` where present. A site with several accounts gets the username in its name (`github.com-octocat`). Importing the same export again changes nothing; a changed password becomes a new version.

Imported logins can't be used by anything until you allow a program: `asiri policy apple/github.com/password --bins psql`.

After importing, asiri overwrites and deletes the file, and tells you if it sat in a folder that iCloud Drive, Dropbox, Google Drive or OneDrive syncs (remove it there too), or if Time Machine may have backed it up. On SSDs and APFS, deleted data can linger until the space is reused: FileVault is what protects it. `--keep` keeps the file.

## 08 hand it to your agent

Give the agent its own profile, then its MCP server and skill:

```sh
asiri clients add claude && asiri pair --profile claude --code <code>
claude mcp add asiri -- asiri mcp --profile claude          # Claude Code; other MCP clients: command `asiri mcp`
mkdir -p ~/.claude/skills/asiri && asiri skill > ~/.claude/skills/asiri/SKILL.md
```

| tool | does |
|---|---|
| `list_secrets` | references, kinds, allowed programs and SSH hosts; never values |
| `run_with_secrets` | runs one program (no shell) with secrets as env, stdin or one-time files; returns exit code and scrubbed output |
| `ssh_run` | runs a command over ssh with an asiri key |
| `request_missing_secret` | asks you to `asiri add` a secret it needs, and waits for it |

There is no tool that returns a value. Approvals go to Rex; without Rex the call waits and its notes say `asiri approve <ID>`. The skill tells the agent the rules: never ask for a secret in the chat, use references, give a reason, call the real program instead of a shell, take a denial as final.

## give an agent its own profile

```sh
asiri clients add claude             # prints a code
asiri pair --profile claude --code <code>
ASIRI_PROFILE=claude asiri ls        # agents can list; they can't add, unlock or read the log
```

## everything else

| command | does |
|---|---|
| `asiri approve [ID] [--for 15m]` / `asiri deny ID` / `asiri pending` | answer waiting requests / list them |
| `asiri rex install` / `uninstall` / `status` | approvals in Rex's command palette |
| `asiri ssh ARGS` / `asiri ssh-agent` / `asiri pubkey REF` | ssh with an asiri key / an agent socket / the public key |
| `asiri import FILE [--dry-run] [--keep] [--vault V]` | import an Apple Passwords or Google Password Manager export |
| `asiri mcp` / `asiri skill` | MCP server on stdio for an agent / print the agent skill |
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

The website is static. Edit documentation in `docs/*.md` and the shared layout in
`docs/layout.html`, then run `go run ./dev docs`. Commit the generated pages and
Markdown under `site/docs/` with their sources. `go run ./dev docs --check` detects
stale output. Preview with `python3 -m http.server 8788 --directory site` and open
`http://localhost:8788/docs/`. Pages deploys the `site/` directory without a build step.

## license

Apache-2.0
