# getting started

Run a local vault, store a token, and approve its use. Run these steps yourself in a terminal. Do not put credentials into an agent conversation.

## before you begin

You need Docker with Compose. A release binary is at https://github.com/gingered-cat/asiri/releases/latest. Building from source also needs Git and the Go toolchain in `go.mod`.

The example uses GitHub CLI (`gh`). Install and sign in to it first if you want to try that example.

## build the CLI

Clone the repository and build the binary for your machine:

```sh
git clone https://github.com/gingered-cat/asiri.git
cd asiri
go run ./dev bin
export PATH="$PWD/bin:$PATH"
```

This PATH change lasts for this terminal session. Keep the binary at a stable path if you install the Rex integration.

## start the vault

Generate a master key. Keep a secure backup of it, separate from your vault backup. Losing the key means losing access to the encrypted secrets.

```sh
asiri server keygen -o ~/.config/asiri/master.key
```

On native Linux Docker, the container runs as user 65532. Give that user ownership of the key file before starting. Docker Desktop and OrbStack handle the file mount differently and do not need this step.

```sh
# native Linux Docker only
sudo chown 65532 ~/.config/asiri/master.key
```

From the repository root, build and start the container:

```sh
docker compose -f deploy/compose.yaml up -d --build
```

The server listens on `127.0.0.1:7420`. It is not exposed to your network. The Docker volume holds the vault and server identity.

## pair your machine

Generate a one-time owner pairing code inside the container:

```sh
docker compose -f deploy/compose.yaml exec asiri asiri server pair-code
```

Run the pairing command it prints. If you copy just the code, replace `CODE` below with it:

```sh
asiri pair --code CODE
asiri status
```

The code expires after ten minutes and works once. It includes the server's CA fingerprint. Pairing refuses a different server before it sends the code.

## store a secret

Add a GitHub token through the hidden terminal prompt:

```sh
asiri add dev/github
asiri ls
```

`asiri ls` shows names and metadata, never secret values. If `gh` is already signed in, you can pipe its token directly instead:

```sh
gh auth token | asiri add dev/github --stdin
```

## approve your first command

Allow only `gh` to receive this token. Then ask it to show your GitHub username:

```sh
asiri policy dev/github --bins gh --max-grant 1h
asiri run --env GH_TOKEN=asiri://dev/github \
  --reason "show my GitHub username" -- gh api user --jq .login
```

Approve once when prompted. The program receives the token. Its output passes through asiri's scrubber before it reaches the terminal.

### if the command waits

If Rex is available, the request appears there. Otherwise a human-run command can ask in the terminal. An agent request waits for you to run the printed `asiri approve ID` command in your own terminal.

Never give an agent your owner profile to remove this step. See [setups](/docs/setups/) for a separate agent profile.

On a Mac, run `asiri touchid enroll`. Then every approval needs Touch ID or your Mac password, so even an agent that reaches your owner profile can't approve. See [Touch ID approvals](/docs/cli/#touch-id-approvals).

### what to do next

Set up [Rex approvals](/docs/rex/) for decisions in your workspace. Read [CLI usage](/docs/cli/) for delivery options and [self-hosting](/docs/self-hosting/) before changing storage or network access.
