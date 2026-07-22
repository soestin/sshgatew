# Operator guide

## Docker Compose

The repository includes `compose.yaml` and a multi-stage `Dockerfile`. Copy an
administrator public key to `admin.pub` and start the gateway:

```sh
SSHGATEW_ADMIN=admin SSHGATEW_VERSION=0.7.1 docker compose up -d --build
docker compose logs sshgatew
```

The first container startup initializes SSHGateW automatically. Preserve both
named volumes: `sshgatew-config` contains the configuration, while
`sshgatew-data` contains the database, master key, and gateway host key. Back
up both volumes together. Rebuilding or replacing the container does not rerun
initialization while the configuration exists.

Useful overrides can be placed in an uncommitted `.env` file:

```dotenv
SSHGATEW_ADMIN=admin
SSHGATEW_ADMIN_KEY_FILE=./admin.pub
SSHGATEW_PORT=2222
SSHGATEW_VERSION=0.7.1
```

Use `docker compose down` to stop the service. Do not add `--volumes` unless
you intend to destroy the installation; deleting either named volume can make
the encrypted credentials unavailable or inconsistent.

## Single-binary bootstrap

On a fresh systemd Linux host:

```sh
chmod +x sshgatew
sudo ./sshgatew install
```

The interactive installer performs the complete service-account, directory,
key, database, configuration, binary, and systemd setup. It does not change the
host firewall. For automation, pass `--admin`, `--authorized-key`, `--listen`,
and `--yes`; add `--no-start` when configuration management will start the
service later.

Installation is intentionally fail-closed when `/etc/sshgatew/config.toml` or
`/var/lib/sshgatew/sshgatew.db` already exists. Existing installations should
be upgraded by replacing the binary and restarting the service, not by running
the bootstrap installer again.

All commands accept `--config PATH` before the subcommand. The default is
`/etc/sshgatew/config.toml`.

## Users and keys

```text
users list
users add USER [--role member|admin]
users enable|disable|delete USER
users set-role USER member|admin
users keys list USER
users keys add USER --file PUBLIC_KEY [--label LABEL]
users keys remove USER SHA256:FINGERPRINT
users totp remove USER
```

SSHGateW prevents removal of the final enabled administrator with a usable
gateway key. A public key may be assigned to multiple users because login
matching includes both the claimed SSH username and key fingerprint. Assigning
the same key twice to one user is rejected.

## Groups and grants

```text
groups list
groups add|delete GROUP
groups members add|remove GROUP USER
grants list
grants add|remove --target TARGET --user USER
grants add|remove --target TARGET --group GROUP
```

Administrators can access every enabled target. Members receive the union of
their direct and group grants.

## Targets

```text
targets list
targets add --name NAME --host HOST [--port 22] --remote-user USER \
  --auth password|private_key|forwarded_agent [--key-file FILE] \
  [--host-key-file FILE | --accept-host-key]
targets edit NAME [--host HOST] [--port PORT] [--remote-user USER]
targets enable|disable|delete NAME
targets credential replace NAME [--auth password|private_key|forwarded_agent] [--key-file FILE]
targets host-key scan NAME
targets host-key replace NAME [--host-key-file FILE | --accept-host-key]
```

`host-key scan` never mutates the pin. A network scan is not identity proof;
compare its SHA-256 fingerprint out-of-band. Host-key changes always require an
explicit replacement operation and produce an audit event.

Secrets are accepted through a hidden terminal prompt or standard input. Avoid
piping secrets on multi-user systems unless the producing process is equally
protected.

### Forwarded-agent and security-key targets

Choose `forwarded_agent` and paste the public key that is authorized on the
downstream server. SSHGateW stores no private key for this mode and restricts
authentication to that exact public key, even if the forwarded agent contains
other identities. Connect with agent forwarding enabled:

```sh
ssh-add ~/.ssh/id_ed25519_sk
ssh -A -p 2222 admin@gateway.example.com
```

The authenticator may request a touch when the target connection starts. The
agent channel is closed immediately after authentication and is never exposed
inside the downstream shell. Without `-A`, SSHGateW returns to the target menu
with an actionable error.

## Remote administrator TUI

Administrators can browse targets, reusable SSH keys, users, groups, grants,
and recent audit events. The interface adapts to the SSH terminal size and paginates long lists.
Resize events redraw it in place without disconnecting the session.

Use Up/Down or `j`/`k` to select, PgUp/PgDn to change pages, Home/End to jump,
Enter to connect, `/` to search, `1`–`6` or Left/Right to change administrator
sections, `?` for help, and `q` to leave. Administrators perform changes through
contextual menus—no command syntax is required. Press `a` to add an item in the
current section. Press Enter or `m` to manage the selected user, group, grant,
or target. Tab moves through form fields and Left/Right changes a choice.

The menus cover target connection settings, credentials, pinned host keys,
enabled state and deletion; reusable downstream SSH keys; user roles, enabled
state and gateway login keys; group membership; and user/group target grants.
Destructive actions require an explicit confirmation.

The `SSH KEYS` tab stores reusable downstream identities. Press `a`, give the
key a name, then choose either `generate_ed25519` or `import_private_key`.
Generated keys expose their public half through the Manage menu so it can be
copied into a downstream `authorized_keys` file. Imported encrypted OpenSSH
keys are supported and their passphrase remains inside the encrypted payload.
When adding a target or replacing its credential, choose `stored_key` and then
select the saved key by name. Keys referenced by targets cannot be deleted.

To enable two-factor authentication, open `USERS`, manage a user, and choose
`Set up TOTP`. Scan the terminal QR code with an authenticator app, press Enter,
then provide the current six-digit code. Enrollment is committed only after
that code succeeds. The user must subsequently enter a TOTP code after SSH-key
authentication and before the gateway menu opens. Each counter value can be
used only once, one adjacent 30-second window is accepted for clock drift, and
the connection closes after five failures.

If an authenticator is lost, another administrator can remove TOTP through the
user's Manage menu. Host administrators can recover locally without entering
the gateway using:

```sh
sudo -u sshgatew sshgatew --config /etc/sshgatew/config.toml users totp remove USER
```

Target addition and host-key replacement scan the server, display the observed
fingerprint, and require `y` confirmation. Passwords and private keys use a
separate hidden input mode. Paste a private key and press Ctrl+D; encrypted keys
then request a hidden passphrase.

## Auditing

```text
audit list [--limit 100]
audit prune --before 2026-01-01T00:00:00Z
```

Audit retention is indefinite until explicitly pruned. Events contain identity,
source address, target, outcome, and safe metadata. They never contain terminal
input/output or credentials.

## Backup and recovery

Back up these files separately and securely:

- `/var/lib/sshgatew/sshgatew.db`
- `/var/lib/sshgatew/master.key`
- `/var/lib/sshgatew/ssh_host_ed25519_key`
- `/etc/sshgatew/config.toml`

The database is unusable for downstream authentication without the exact master
key. Losing the gateway host key causes SSH clients to report a changed gateway
identity. Stop the daemon or use SQLite's online backup mechanism before copying
the live database.
