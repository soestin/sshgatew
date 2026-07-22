package store

import "time"

const (
	RoleAdmin            = "admin"
	RoleMember           = "member"
	CredentialPassword   = "password"
	CredentialPrivateKey = "private_key"
	CredentialAgent      = "forwarded_agent"
)

type User struct {
	ID             int64
	Username, Role string
	Enabled        bool
	CreatedAt      time.Time
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
	CreatedAt, UpdatedAt                       time.Time
}
type AuditEvent struct {
	ID                                        int64
	At                                        time.Time
	ActorUserID                               *int64
	ClaimedUsername, SourceAddress, EventType string
	TargetID                                  *int64
	Outcome, Details                          string
}
type Grant struct{ Target, Kind, Principal string }
type GroupMember struct{ Group, Username string }
