package store

import "time"

const (
	RoleAdmin            = "admin"
	RoleMember           = "member"
	CredentialPassword   = "password"
	CredentialPrivateKey = "private_key"
	CredentialAgent      = "forwarded_agent"
	CredentialStoredKey  = "stored_key"
	CapabilityShell      = "shell"
	CapabilitySFTP       = "sftp"
	CapabilitySCP        = "scp"
	CapabilityForward    = "tcp_forward"
)

type User struct {
	ID             int64
	Username, Role string
	Enabled        bool
	TOTPEnabled    bool
	CreatedAt      time.Time
}
type TOTPConfig struct {
	UserID            int64
	Nonce, Ciphertext []byte
	LastCounter       int64
}
type GatewayKey struct {
	ID, UserID                    int64
	Fingerprint, PublicKey, Label string
	CreatedAt                     time.Time
}
type Group struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}
type Target struct {
	ID                                         int64
	Name, Host, RemoteUsername, CredentialKind string
	Port                                       int
	Enabled                                    bool
	HostKeyAlgorithm, HostPublicKey            string
	Nonce, Ciphertext                          []byte
	IdentityID                                 *int64
	CreatedAt, UpdatedAt                       time.Time
}
type SSHIdentity struct {
	ID                           int64
	Name, PublicKey, Fingerprint string
	Nonce, Ciphertext            []byte
	CreatedAt                    time.Time
}
type AuditEvent struct {
	ID                                        int64
	At                                        time.Time
	ActorUserID                               *int64
	ClaimedUsername, SourceAddress, EventType string
	TargetID                                  *int64
	Outcome, Details                          string
}
type Grant struct {
	Target, Kind, Principal      string
	Shell, SFTP, SCP, TCPForward bool
}
type ForwardRule struct {
	ID, TargetID int64
	Target, Host string
	Port         int
}
type GroupMember struct{ Group, Username string }
