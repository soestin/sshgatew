# SSHGateW

SSHGateW is a self-hosted SSH credential gateway. Team members authenticate to
the gateway with their own SSH public keys, choose an authorized connection
profile in a terminal UI, and receive a transparent interactive shell on the
downstream machine. Downstream passwords and private keys stay on the gateway,
encrypted at rest.

## Current features

- Public-key authentication to the gateway on port 2222 by default.
- Member and administrator terminal interfaces.
- Per-user and per-group target grants.
- Password, stored private-key, and restricted forwarded-agent authentication.
- Exact downstream host-key pinning; changed keys are rejected.
- XChaCha20-Poly1305 encrypted credentials with a separate master-key file.
- SQLite persistence, metadata auditing, session limits, and JSON logs.
- No remote exec, SFTP, SCP, TCP forwarding, downstream agent exposure, or terminal recording.

## Build

Go 1.26 or newer is required.

```sh
make build VERSION=0.1.0
```

## Initialize a Linux server

Create the service account and protected directories:

```sh
sudo useradd --system --home /var/lib/sshgatew --shell /usr/sbin/nologin sshgatew
sudo install -d -o sshgatew -g sshgatew -m 0750 /var/lib/sshgatew
sudo install -d -o sshgatew -g sshgatew -m 0750 /etc/sshgatew
sudo install -o root -g root -m 0755 sshgatew /usr/local/bin/sshgatew
```

Initialize with an existing administrator public key:

```sh
sudo -u sshgatew /usr/local/bin/sshgatew \
  --config /etc/sshgatew/config.toml \
  init --admin admin --authorized-key /path/readable/by/sshgatew/admin.pub
sudo chown root:sshgatew /etc/sshgatew/config.toml /etc/sshgatew
sudo chmod 0640 /etc/sshgatew/config.toml
sudo chmod 0750 /etc/sshgatew
```

Install `deploy/sshgatew.service`, open TCP port 2222 in the host firewall, and
start the service:

```sh
sudo install -o root -g root -m 0644 deploy/sshgatew.service /etc/systemd/system/sshgatew.service
sudo systemctl daemon-reload
sudo systemctl enable --now sshgatew
sudo systemctl status sshgatew
```

Connect with:

```sh
ssh -p 2222 admin@gateway.example.com
```

Verify the gateway host-key fingerprint printed by `sshgatew init` before
accepting it in the SSH client.

## Add a password target

First verify the downstream server's SSH host fingerprint through a trusted
channel. The initial command prints the observed fingerprint but refuses to
store it:

```sh
sudo -u sshgatew sshgatew targets add \
  --name production --host 10.0.0.10 --port 22 --remote-user deploy \
  --auth password
```

After verification, repeat with `--accept-host-key`. The password is read from
a hidden prompt, never an argument:

```sh
sudo -u sshgatew sshgatew targets add \
  --name production --host 10.0.0.10 --port 22 --remote-user deploy \
  --auth password --accept-host-key
sudo -u sshgatew sshgatew grants add --target production --group operators
```

For private-key authentication, use `--auth private_key --key-file PATH`.
Encrypted OpenSSH private keys are supported and their passphrases are stored
inside the encrypted credential payload.

For a FIDO/YubiKey or another local-agent identity, choose `forwarded_agent`
in the TUI or use `--auth forwarded_agent --key-file PUBLIC_KEY`. Connect to
the gateway with `ssh -A`. SSHGateW permits only the configured public key and
closes the agent channel immediately after downstream authentication.

Run local administration commands as the `sshgatew` service user to avoid
creating SQLite WAL files with incompatible ownership.

See [the operator guide](docs/operations.md) and
[security model](docs/security.md) for the complete command and recovery
workflow.
