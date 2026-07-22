# SSHGateW MVP Implementation Plan

## Summary

Build SSHGateW as a Linux-focused Go application that listens on TCP port `2222`, authenticates gateway users with registered SSH public keys, presents an interactive TUI, and transparently bridges users into authorized downstream SSH connection profiles.

The MVP will support:

- A small trusted team with named users and multiple gateway keys per user.
- `admin` and `member` roles.
- User- and group-based target grants.
- Downstream authentication using stored private keys or passwords.
- Encrypted local credential storage.
- Explicitly pinned downstream host keys.
- A complete local administration CLI.
- Day-to-day administration through an admin-only TUI.
- Durable metadata auditing without terminal recording.
- One daemon, one SQLite database, and local protected key files.

## Technology and Repository Structure

Initialize the empty workspace as a Go module named `sshgatew`, with this structure:

```text
cmd/sshgatew/          CLI entrypoint
internal/config/       TOML loading, defaults, validation
internal/store/        SQLite schema, migrations, repositories
internal/secrets/      Credential encryption and master-key handling
internal/auth/         Gateway public-key authentication and authorization
internal/gateway/      Inbound SSH server and session lifecycle
internal/downstream/   Downstream dialing, verification, and terminal bridge
internal/tui/          Member and administrator Bubble Tea models
internal/audit/        Structured audit event creation
deploy/                systemd unit and installation examples
docs/                  Operator and security documentation
```

Use:

- `github.com/charmbracelet/ssh` for the inbound SSH server.
- `github.com/charmbracelet/bubbletea/v2` and compatible Bubbles components for the TUI.
- `golang.org/x/crypto/ssh` for downstream connections.
- A current `golang.org/x/crypto` release no older than `v0.52.0`, avoiding the SSH resource-leak vulnerability affecting earlier releases. [Go vulnerability report](https://pkg.go.dev/vuln/GO-2026-5017)
- `modernc.org/sqlite` for an embedded, CGO-free SQLite driver.
- `github.com/pelletier/go-toml/v2` for configuration.
- XChaCha20-Poly1305 from `golang.org/x/crypto/chacha20poly1305` for credential encryption.

## Executable and CLI Interface

Produce one binary named `sshgatew`.

Global option:

```text
--config <path>    Default: /etc/sshgatew/config.toml
```

Commands:

```text
sshgatew init --admin <username> --authorized-key <path>
sshgatew serve

sshgatew users list
sshgatew users add <username> [--role member|admin]
sshgatew users disable|enable|delete <username>
sshgatew users set-role <username> <member|admin>
sshgatew users keys list <username>
sshgatew users keys add <username> --file <path> [--label <label>]
sshgatew users keys remove <username> <fingerprint>

sshgatew groups list
sshgatew groups add|delete <group>
sshgatew groups members add|remove <group> <username>

sshgatew targets list
sshgatew targets add
sshgatew targets edit <name>
sshgatew targets enable|disable|delete <name>
sshgatew targets credential replace <name>
sshgatew targets host-key scan <name>
sshgatew targets host-key replace <name>

sshgatew grants list
sshgatew grants add|remove --target <name> --user <username>
sshgatew grants add|remove --target <name> --group <group>

sshgatew audit list [filters]
sshgatew audit prune --before <RFC3339 timestamp>
```

CLI behavior:

- `init` creates the database, migrations, 32-byte master key, Ed25519 gateway host key, and first administrator.
- Initialization fails rather than overwriting existing state.
- Passwords, private keys, and private-key passphrases must never be accepted as command-line flags.
- Secret values are read from a no-echo prompt or standard input.
- Private keys are parsed and validated before storage.
- Interactive target creation prompts for name, host, port, remote username, credential type, credential, and host-key confirmation.
- Automation may supply an exact OpenSSH-formatted host public key instead of scanning.
- Secret replacement is write-only; neither CLI nor TUI can reveal stored credentials.
- Destructive operations require confirmation unless an explicit noninteractive confirmation flag is supplied.
- Local CLI operations enforce the same invariants as TUI operations. A clearly named `--force` escape hatch may only exist for recovery by a local server administrator.

## Configuration Interface

Use TOML with this initial schema:

```toml
listen_address = "0.0.0.0:2222"
database_path = "/var/lib/sshgatew/sshgatew.db"
master_key_path = "/var/lib/sshgatew/master.key"
host_key_path = "/var/lib/sshgatew/ssh_host_ed25519_key"

idle_timeout = "30m"
downstream_dial_timeout = "10s"
max_sessions = 100
max_sessions_per_user = 5

log_level = "info"
log_format = "json"
```

Rules:

- Configuration contains paths and operational settings, never credentials.
- Reject invalid addresses, nonpositive limits, unknown mandatory enum values, and malformed durations.
- The daemon refuses startup if the master key or host private key is missing, malformed, group/world-readable, or not a regular file.
- Database and data directory permission problems produce actionable errors.
- SQLite uses WAL mode, foreign keys, and a five-second busy timeout.

## Persistent Data Model

Use versioned SQLite migrations and the following logical tables:

- `schema_migrations`
- `users`
  - ID, normalized unique username, role, enabled state, timestamps.
- `gateway_keys`
  - User ID, canonical public key, SHA-256 fingerprint, label, timestamps.
  - A key fingerprint may belong to only one gateway user.
- `groups`
  - ID, unique name, timestamps.
- `group_members`
  - Group ID and user ID.
- `targets`
  - ID, unique display name, host, port, remote username, credential kind, encrypted credential, pinned host-key algorithm/blob, enabled state, timestamps.
- `user_target_grants`
  - User ID and target ID.
- `group_target_grants`
  - Group ID and target ID.
- `audit_events`
  - Timestamp, actor user where known, claimed username where relevant, source address, event type, target where relevant, outcome, safe JSON metadata.

Usernames are lowercase and match:

```text
[a-z][a-z0-9_-]{0,31}
```

A target represents a complete connection profile. Multiple profiles may point to the same hostname with different usernames or credentials.

Admins implicitly receive access to every enabled target. Members see the union of their direct and group grants.

Prevent states that leave no enabled administrator with at least one registered key. Remote admins cannot remove their own final working login path.

## Credential Encryption

Use one randomly generated 32-byte master key stored separately from SQLite with mode `0600`.

For each credential:

- Generate a fresh 24-byte XChaCha20-Poly1305 nonce.
- Encrypt a versioned credential payload.
- Authenticate stable associated data containing the schema version, target ID, and credential kind.
- Store nonce and ciphertext, never plaintext.
- Treat authentication failures as corruption or wrong-key errors and never attempt a downstream connection.

Credential payload variants:

```text
password:
  password

private_key:
  original private-key bytes
  optional private-key passphrase
```

Private-key and password buffers should be cleared on a best-effort basis after use. Documentation must explain that both the database and master key are required for recovery and should be backed up separately.

## Gateway SSH Server

Default listener: `0.0.0.0:2222`.

Inbound authentication:

- MVP supports public-key authentication only.
- The SSH username must identify an enabled gateway user.
- The presented public key must exactly match one of that user’s registered keys.
- Multiple keys per user are supported.
- Record successful and failed authentication metadata.
- Never enable an unauthenticated fallback when handlers are absent.

Session restrictions:

- Require an interactive SSH session with a PTY.
- Deny remote command execution, subsystems, SFTP/SCP, direct TCP forwarding, reverse forwarding, and agent forwarding.
- Reject unsupported channel types.
- Enforce global and per-user session limits.
- Cancel active work when the client disconnects.
- Use safe modern Go SSH defaults; do not re-enable obsolete algorithms merely for compatibility.

## Member TUI

After successful login, show a full-screen target browser containing only authorized, enabled profiles.

Features:

- Target name, host, port, and remote username.
- Search/filter as the user types.
- Keyboard navigation, help, connect, refresh, and quit.
- Clear empty-state messaging when no targets are granted.
- Connection progress and concise failure messages.
- On downstream logout or connection failure, return to a newly rendered target menu.
- Never display credential contents.

Terminal ownership must be unambiguous:

1. Run the Bubble Tea menu.
2. When a target is selected, cleanly exit the TUI and restore terminal modes.
3. Run the downstream bridge as the sole reader/writer of the SSH channel.
4. When it ends, start a fresh TUI instance with a status notification.

## Administrator TUI

Admins receive additional sections for:

- Users and gateway keys.
- Groups and membership.
- Targets and credential replacement.
- User/group grants.
- Recent audit events.

The TUI supports the same day-to-day CRUD operations as the CLI, excluding bootstrap, daemon configuration, and bulk audit pruning.

Secret entry requirements:

- Password fields are masked.
- Pasted private keys are retained only in memory and represented by a placeholder or line count, never rendered back to the terminal.
- Existing secrets are shown only as credential type and replacement status.
- Host-key scans display the algorithm and SHA-256 fingerprint and require explicit confirmation.
- Deletions, key rotation, credential rotation, and host-key replacement require confirmation.

## Downstream SSH Connection

For a selected target:

1. Re-check authorization and target enabled state immediately before dialing.
2. Load and decrypt the credential only after authorization succeeds.
3. Dial with the configured timeout.
4. Verify the server’s exact stored host public key.
5. Abort on unknown, missing, or changed host keys before completing authentication.
6. Authenticate with either:
   - SSH password authentication, or
   - the stored private key and optional passphrase.
7. Request a downstream PTY using the inbound terminal type and initial dimensions.
8. Start the downstream interactive shell.
9. Bridge stdin, stdout, and stderr without interpreting terminal contents.
10. Forward inbound resize events with `WindowChange`.
11. Propagate supported SSH signals on a best-effort basis.
12. Close both downstream session and client deterministically on exit or cancellation.

Password-based keyboard-interactive authentication is not part of the MVP; the password credential uses the SSH password method.

A host-key scan is advisory until an administrator confirms it. Rotation always requires explicit replacement; SSHGateW must never silently trust a changed key.

## Audit and Operational Logging

Durable audit events include:

- Gateway authentication success and failure.
- Gateway session start and end.
- Downstream connection attempt, success, failure, and end.
- Target and host-key rotations.
- Credential replacement.
- User, key, group, membership, and grant changes.
- Actor, source address, target, outcome, safe error category, duration, and downstream exit status where available.

Never retain:

- Terminal input or output.
- Commands typed in the downstream shell.
- Passwords, private keys, passphrases, decrypted payloads, or authentication callback contents.

Audit events are retained indefinitely by default. Operators explicitly remove old records with `audit prune`.

Operational logs go to stderr as structured JSON for systemd/journald. Error messages and audit metadata must be sanitized before logging.

## Linux Deployment

Provide:

- Linux amd64 and arm64 build instructions.
- A dedicated unprivileged `sshgatew` service account.
- `/etc/sshgatew/config.toml`.
- `/var/lib/sshgatew` owned by the service account with restrictive permissions.
- A hardened example systemd unit.
- Restart and graceful shutdown behavior for `SIGTERM`/`SIGINT`.
- Documentation for firewalling port `2222`, registering the gateway host fingerprint, backups, recovery, and downstream host-key rotation.

The systemd service should include `NoNewPrivileges`, private temporary storage, a read-only system filesystem, and write access limited to `/var/lib/sshgatew`. It needs outbound IPv4/IPv6 access for downstream SSH.

## Internal Interfaces

Keep packages internal but establish testable boundaries:

```go
type Store interface {
    AuthenticateGatewayKey(...)
    ListAuthorizedTargets(...)
    ManageUsersGroupsTargetsAndGrants(...)
    AppendAuditEvent(...)
}

type CredentialCipher interface {
    Encrypt(targetID, kind, plaintext ...)
    Decrypt(targetID, kind, ciphertext ...)
}

type Connector interface {
    Connect(context.Context, Target, Credential, Terminal) error
}

type Auditor interface {
    Record(context.Context, Event) error
}
```

Use typed enums for:

- `Role`: `admin`, `member`
- `CredentialKind`: `private_key`, `password`
- `PrincipalKind`: `user`, `group`
- `AuditOutcome`: `success`, `failure`, `denied`

The CLI and TOML configuration are public operator interfaces. The SQLite schema remains internal and must only be modified through migrations and application commands.

## Failure Handling

- Database migration failure prevents startup.
- Missing or incorrect master key prevents startup or credential use with a clear diagnostic.
- Audit-write failures during security-sensitive administration abort the associated mutation transaction.
- Authentication audit failures are logged operationally but must not accidentally grant access.
- Authorization is checked both when rendering targets and immediately before connection.
- Host mismatch, credential failure, timeout, DNS failure, and unreachable host return distinct sanitized messages.
- Downstream failures return users to the menu without terminating the gateway session.
- If the inbound client disconnects, all downstream goroutines and sockets terminate.
- Concurrent CLI/TUI mutations use transactions and surface conflicts rather than silently overwriting newer values.

## Testing

### Unit tests

- Configuration defaults, parsing, and validation.
- Master-key and file-permission checks.
- Encryption round trips for both credential kinds.
- Random nonce usage, associated-data mismatch, tampering, and wrong-key rejection.
- Public-key matching, disabled users, username mismatch, and duplicate key rejection.
- Direct/group/admin authorization resolution.
- Last-administrator and final-login-key invariants.
- Host-key exact-match and changed-key rejection.
- Audit sanitization to prove known secret values cannot appear.
- TUI navigation, filtering, role visibility, confirmation flows, and masked secret models.

### Storage tests

- All migrations from an empty database.
- CRUD and cascading behavior for every entity.
- Unique constraints and foreign keys.
- Transaction rollback when audit insertion fails.
- Concurrent reads/writes under WAL mode.
- Credential rotation without changing target grants.
- Host-key replacement audit trail.

### SSH integration tests

Use in-process test SSH servers where possible:

- Valid and invalid gateway public-key authentication.
- Member sees only directly and indirectly granted targets.
- Admin sees all enabled targets.
- PTY requirement enforcement.
- Denial of exec, subsystem, SFTP, and forwarding requests.
- Downstream password authentication.
- Downstream encrypted and unencrypted private-key authentication.
- Terminal byte bridging and downstream exit handling.
- Window-resize forwarding.
- Host-key mismatch blocks the connection.
- Verify downstream authentication is not completed when host verification fails.
- Gateway disconnect cancels downstream activity.
- Session limits behave correctly.

### CLI and system tests

- Initialize into temporary paths and refuse reinitialization.
- Exercise secret input through stdin without command-line exposure.
- Restart the daemon and confirm users, grants, targets, and credentials persist.
- Validate generated file modes.
- Verify graceful systemd-style shutdown.
- Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and `govulncheck ./...`.

## Acceptance Criteria

The MVP is complete when:

- `ssh -p 2222 alice@gateway` authenticates using Alice’s registered public key.
- Alice receives a usable TUI containing only her authorized profiles.
- Selecting a profile opens a fully interactive downstream shell with correct resize behavior.
- Both stored password and private-key profiles work.
- Logging out of the downstream machine returns Alice to the gateway menu.
- A changed downstream host key blocks the connection.
- Admins can manage users, keys, groups, targets, credentials, and grants through both the local CLI and admin TUI.
- State survives daemon restarts.
- Stored credential plaintext cannot be recovered from the SQLite file alone.
- Metadata auditing is durable and contains no terminal contents or secrets.
- Unsupported SSH features are denied.
- Automated tests cover authentication, authorization, encryption, pinning, bridging, and administrative invariants.

## Explicit Assumptions and Out-of-Scope Items

Assumptions:

- MVP servers run Linux on amd64 or arm64.
- SSHGateW is operated by a small trusted team.
- Each connection profile has one shared downstream identity and credential.
- Operators protect the host, database, master-key file, and backups.
- The local CLI is restricted through normal Linux ownership and root/service-account access.

Out of scope for the MVP:

- Gateway password, keyboard-interactive, MFA, OIDC, or LDAP authentication.
- SSH certificates, external agents, or dynamic secret managers.
- Web UI or public management API.
- High availability, multiple gateway nodes, or an external database.
- Direct proxy mode such as `ProxyJump`.
- SCP, SFTP, remote exec, and port forwarding.
- Full terminal recording or command inspection.
- Automatic trust-on-first-use.
- macOS and Windows service support.
