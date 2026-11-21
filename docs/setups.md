# setups

Choose how you approve requests and which identity each agent uses. All setups start with a vault and an owner profile from [getting started](/docs/getting-started/).

## a person in a terminal

Run `asiri run` from your own terminal. If Rex is available, it handles approval. Otherwise an interactive terminal can ask directly.

```sh
asiri run --env GH_TOKEN=asiri://dev/github \
  --reason "check my account" -- gh api user --jq .login
```

Return allows once. In the terminal prompt, `f` allows 15 minutes, `h` allows an hour, and `d` denies, subject to the secret's policy.

## an agent with Rex

Install Rex support as the owner:

```sh
asiri rex install
```

Create a separate client identity for the agent:

```sh
asiri clients add claude
```

Use the code it prints to pair the agent profile:

```sh
asiri pair --profile claude --code CODE
ASIRI_PROFILE=claude asiri ls
```

Set `ASIRI_PROFILE=claude` in the agent process's environment. For example, if you use Claude Code, launch it from that environment:

```sh
ASIRI_PROFILE=claude claude
```

This selects the profile. It is not an operating-system sandbox. Keep owner credentials outside the agent's reach, especially when it can read arbitrary files as your user.

### give the agent the instructions

The [agent skill](/skill.md) explains the secret-reference workflow. The “copy page as markdown” action on each documentation page copies that page's source for your agent.

Provide the skill and the relevant documentation page. Never include a token, password, private key, or pairing code in a shared conversation.

## an agent without Rex

The same agent profile works without Rex. Leave the agent request waiting. In a separate owner terminal, inspect and answer it:

```sh
asiri pending
asiri approve ID
```

Use `asiri deny ID` to refuse. Do not run the approval command through the agent profile or give the agent owner access to make the prompt disappear.

## git and SSH tools

First create a host-bound SSH key as described in [CLI usage](/docs/cli/#ssh-keys). Start the socket service in one terminal:

```sh
asiri ssh-agent
```

In the terminal where you use Git or rsync, point OpenSSH at the socket:

```sh
export SSH_AUTH_SOCK=~/.asiri/agent.sock
git push
```

Only allowed hosts can use the key. The server signs the SSH login without sending the private key to the client. Agent forwarding, `ssh-add`, and non-login signatures are refused.

## remove an agent's access

Inspect the client list and revoke the client by name:

```sh
asiri clients ls
asiri clients revoke claude
asiri revoke --all
```

The last command also revokes other clients' grants and denies pending requests. Use it only when you intend that wider effect. It does not undo commands that already ran.
