# human + agent, in harmony

Dedicated to a way of working where humans keep their agency and agents can do useful work. Neither needs to pretend to be the other.

*Àṣírí* is Yoruba for “secret.” The name describes what stays yours, even when an agent helps you use it.

## collaboration, with boundaries

An agent can open a pull request without knowing your GitHub token. It can connect to a server without holding your private key. Useful access does not require unrestricted access.

asiri separates the work from the credential. The agent names a secret and explains the task. You decide whether the program receives it.

### the human decides

Approval belongs to you. You can allow one use, grant a short window, or say no. An agent profile cannot approve its own request. A denial is a decision, not a puzzle for the agent to solve.

### the agent does the work

The agent receives the program's result, not a tool for reading the vault. Secret references such as `asiri://dev/github` give people and agents a shared vocabulary without putting values in the conversation.

## consent stays visible

The approval shows the program, arguments, working directory, and reason. [Rex](/docs/rex/) brings that decision into your workspace. A terminal approval works without Rex.

A grant is temporary permission. You can inspect grants, revoke them, or lock the vault. The audit log records decisions and changes so that you can review what happened.

## trust has limits

asiri is not a sandbox for arbitrary programs. An allowed program can use a credential to send data elsewhere. Output scrubbing catches known representations of a secret, not every possible transformation.

Environment variables can be visible to other processes running as your user. A compromised host, an owner profile in the wrong hands, or an overly broad allow-list breaks the intended boundary.

Choose programs deliberately. Keep owner credentials away from agents. Treat scrubbing as a safety net, not proof that an untrusted program is safe.

## start with one useful task

Start small: one secret, one allowed program, one approval. Understand the boundary before you widen it.

[Get started](/docs/getting-started/) with a local vault, then give your agent its own profile. The aim is less friction without less consent.
