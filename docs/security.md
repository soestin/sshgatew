# Security model

SSHGateW is a privileged credential broker. Compromise of its process, service
account, master key plus database, or administrator identities can expose every
downstream credential it manages. Harden and monitor the host accordingly.

## Security boundaries

- Gateway users authenticate with an exact registered public-key fingerprint
  under the SSH username they claim.
- Users with TOTP enabled must also pass an application-level RFC 6238 challenge
  before target metadata or the gateway menu becomes available. A code counter
  cannot be reused and five failures close the connection.
- Authorization is checked when listing targets and again immediately before a
  downstream connection.
- Downstream host public keys are pinned exactly. Unknown and changed keys fail
  before downstream authentication completes.
- Credential payloads use XChaCha20-Poly1305 with random nonces and associated
  data binding them either to the target ID and credential type or to a reusable
  SSH-key ID in a separate cryptographic namespace.
- The 32-byte master key and Ed25519 gateway host key must be regular files with
  no group/world permission bits. The SQLite database is mode 0600.
- Passwords, private keys, passphrases, terminal contents, and downstream
  commands are excluded from logs and audit records.
- TOTP seeds are encrypted under the master key with associated data binding
  each seed to its user ID. Seeds and submitted codes are never logged or
  included in audit metadata.
- Forwarded-agent targets pin one exact public key. The agent is used only for
  the downstream authentication handshake and its channel is then closed.

## Deliberately denied SSH features

The gateway accepts interactive PTY shell sessions only. Remote exec, SFTP,
SCP, subsystems, local/reverse TCP forwarding, downstream agent forwarding, and
arbitrary channel types are not enabled. An inbound agent channel is accepted
only when a selected target explicitly uses `forwarded_agent`; it is restricted
to the target's pinned identity and closed before the shell starts. This
prevents the gateway account from becoming a general-purpose tunnel,
file-transfer endpoint, or agent-forwarding hop.

## Operational recommendations

- Restrict port 2222 to trusted networks where possible.
- Keep the OS and SSHGateW dependencies patched; run `govulncheck ./...` before
  releases.
- Verify all gateway and downstream host fingerprints out-of-band.
- Use distinct downstream profiles where different teams need different remote
  identities.
- Protect backups at least as strongly as the live gateway.
- Review authentication failures, administrative changes, credential rotations,
  and host-key rotations in the audit log.
- Prefer private-key downstream authentication over passwords where practical.
