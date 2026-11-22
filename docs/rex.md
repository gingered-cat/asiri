# rex support

Approve an agent's request without leaving your workspace. asiri integrates with the command palette in [Rex](https://www.superlogical.com/rex).

## install the integration

First finish [getting started](/docs/getting-started/). You need a paired owner profile, a built asiri binary at a stable path, and the Rex CLI on PATH.

```sh
curl -fsSL https://asiri.run/install.sh | sh
asiri rex status
```

The script installs the release binary and then runs `asiri rex install` when Rex and an owner profile are already present. If either is missing, run the plugin step yourself after pairing:

```sh
asiri rex install
```

The installer adds asiri's marked block to Rex's `init.lua`. It runs `rex config check` and restores the previous configuration if validation fails. It reloads Rex when possible. If Rex is not running, start it to load the integration.

Do not install from `go run ./cmd/asiri`. That binary lives in a temporary directory. Use the binary built by `go run ./dev bin`.

### choose an owner profile

The integration approves as `owner` by default. If your owner profile has another name, pass it explicitly:

```sh
asiri rex install --profile personal
```

The profile must already exist and have the owner role. Installation refuses an agent profile.

## answer a request

When an agent requests access, connected Rex apps show the secret reference and the proposed command:

```text
claude wants asiri://dev/github
  › Allow once       gh pr create --fill · ~/proj/api · "open the PR"
    Allow for 15 minutes
    Allow for 1 hour
    Deny
```

Return allows once. Closing the prompt denies. When several Rex apps show the request, the first answer wins.

The plugin records the answer using your owner profile. The requesting agent cannot approve itself. Longer grants are still limited by the secret's `--max-grant` policy.

With [Touch ID approvals](/docs/cli/#touch-id-approvals), choosing an Allow option opens a macOS prompt that says exactly what you allow. Confirm it with Touch ID or your password. Deny needs no confirmation.

## use the command palette

Press `Cmd+Shift+P` in Rex and type `asiri`:

| action | result |
| --- | --- |
| Asiri: Approve Waiting Requests… | Inspect and answer pending requests. |
| Asiri: Revoke Everything | Revoke all grants and deny pending requests. |
| Asiri: Lock the Vault | Lock the vault until you unlock it. |

Revoking a grant stops future uses. It does not erase a secret already delivered to a running program.

## when Rex is unavailable

Rex is optional. A command you run yourself can ask in the terminal. An agent command waits and prints the approval command for you.

In your own terminal, inspect the pending request before answering:

```sh
asiri pending
asiri approve ID
# or refuse it
asiri deny ID
```

Replace `ID` with the request identifier. If you want a different Rex server, set `ASIRI_REX_SERVER` to its host label or socket path in the environment of the requesting process.

### troubleshoot the connection

Run `asiri status` to check the vault connection. Run `asiri rex status` to check installation. Make sure a Rex app is connected and the installed binary still exists at its original path.

If you moved the binary, rerun `asiri rex install` from its new location. Do not solve an approval failure by giving the agent an owner profile.

## remove the integration

```sh
asiri rex uninstall
```

This removes asiri's integration from Rex. It does not remove your vault or disable terminal approvals.
