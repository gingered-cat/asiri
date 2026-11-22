# self-hosting

The default deployment is a vault on your own machine. The public asiri website hosts documentation, not your secrets.

## the local boundary

The Compose file publishes only `127.0.0.1:7420`. The server uses mutual TLS: clients authenticate with certificates, and clients pin the server CA during pairing.

The container runs as user 65532, drops Linux capabilities, and has a read-only root filesystem. The `/data` volume remains writable. Keep it private and back it up.

Do not expose this port publicly just to let an agent connect. An agent on the same machine can use the local CLI with its own profile.

## build and run

Follow [getting started](/docs/getting-started/) to create a key and pair an owner. From the repository root:

```sh
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml ps
docker compose -f deploy/compose.yaml logs --tail 50 asiri
```

The `--build` flag builds the server from your checkout. Without it, Compose uses the published `0.1` image by default. Set `ASIRI_VERSION=v0.1.1` to pin an exact release. Keep the host CLI and server on compatible releases.

### key-file mode

The default Compose file mounts `~/.config/asiri/master.key` as a Docker secret. `ASIRI_KEY_FILE` can point Compose at another key file on the host.

The server unlocks from that file. Protect the file and its backups. On native Linux Docker, user 65532 must be able to read it. Do not make the key world-readable.

### passphrase mode

Choose this before creating a new vault. It is not a migration procedure for an existing key-file vault.

Remove both the service's `secrets` entry and the top-level `secrets` section from your local Compose file. Build the image, then initialize the empty vault interactively:

```sh
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml run --rm -it asiri \
  server init --passphrase
docker compose -f deploy/compose.yaml up -d
```

Pair your owner profile using `server pair-code`. Run `asiri unlock` and type the passphrase after each server start. Do not pass the passphrase in command arguments or an agent conversation.

## persistence and backups

Back up the entire `/data` directory, not only the database file. It also contains the server's identity. Back up the master key separately, or keep the passphrase in a secure recovery location.

For a consistent filesystem backup, stop the service first:

```sh
docker compose -f deploy/compose.yaml stop asiri
docker compose -f deploy/compose.yaml cp asiri:/data ./asiri-backup
docker compose -f deploy/compose.yaml start asiri
```

Choose a new backup destination each time. Protect that directory and test recovery on an isolated machine before depending on it. Do not use `docker compose down -v`: it deletes the vault volume.

## updating

Make a backup before updating. Review the source changes and any migration instructions. Rebuild the host CLI and the server from the same revision:

```sh
go run ./dev bin
docker compose -f deploy/compose.yaml up -d --build
asiri status
```

In passphrase mode, run `asiri unlock` after the restart. If the binary path changed, reinstall the [Rex integration](/docs/rex/).

## connection problems

If `asiri status` cannot connect, inspect the container status and logs. Make sure that port 7420 is free and the key file is readable by the container user.

If pairing fails, generate a fresh code. Do not bypass certificate checks. Replacing the server identity requires deliberate pairing with the new server.

Remote hosting changes the trust and network boundary. Configure private networking, firewall rules, and certificate host names before pairing remote clients. The local Compose example is not a public-internet deployment guide.
