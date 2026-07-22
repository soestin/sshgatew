package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestLegacyDatabaseMigratesForForwardedAgentTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY);
INSERT INTO schema_migrations(version) VALUES(1);
CREATE TABLE targets(
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE BINARY, host TEXT NOT NULL,
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535), remote_username TEXT NOT NULL,
 credential_kind TEXT NOT NULL CHECK(credential_kind IN ('password','private_key')),
 credential_nonce BLOB, credential_ciphertext BLOB,
 host_key_algorithm TEXT NOT NULL, host_public_key TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO targets(name,host,port,remote_username,credential_kind,host_key_algorithm,host_public_key)
 VALUES('existing','127.0.0.1',22,'root','private_key','ssh-ed25519','ssh-ed25519 AAAA');`)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.TargetByName(context.Background(), "existing"); err != nil {
		t.Fatalf("existing target was not preserved: %v", err)
	}
	if _, err = store.AddTarget(context.Background(), NewTarget{Name: "agent", Host: "127.0.0.1", Port: 22, RemoteUsername: "root", CredentialKind: CredentialAgent, HostKeyAlgorithm: "ssh-ed25519", HostPublicKey: "ssh-ed25519 AAAA"}); err != nil {
		t.Fatalf("forwarded-agent target rejected after migration: %v", err)
	}
	var version int
	if err = store.DB().QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 6 {
		t.Fatalf("migration version=%d err=%v", version, err)
	}
}
func TestTOTPStorageAndReplayProtection(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	u, err := s.AddUser(ctx, "alice", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetUserTOTP(ctx, u.ID, []byte("nonce"), []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	u, err = s.UserByID(ctx, u.ID)
	if err != nil || !u.TOTPEnabled {
		t.Fatalf("user=%#v err=%v", u, err)
	}
	if err = s.ConsumeTOTPCounter(ctx, u.ID, 42); err != nil {
		t.Fatal(err)
	}
	if err = s.ConsumeTOTPCounter(ctx, u.ID, 42); err == nil {
		t.Fatal("replayed TOTP counter was accepted")
	}
	if err = s.ConsumeTOTPCounter(ctx, u.ID, 41); err == nil {
		t.Fatal("older TOTP counter was accepted")
	}
	if err = s.RemoveUserTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolCapabilitiesAndForwardRules(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	u, err := s.AddUser(ctx, "operator", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	target, err := s.AddTarget(ctx, NewTarget{Name: "prod", Host: "127.0.0.1", Port: 22, RemoteUsername: "root", CredentialKind: CredentialPassword, HostKeyAlgorithm: "ssh-ed25519", HostPublicKey: "ssh-ed25519 AAAA"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetGrantCapabilities(ctx, "prod", "user", u.Username, true, true, true, false, true); err != nil {
		t.Fatal(err)
	}
	if !s.CanAccessCapability(ctx, u, target.ID, CapabilityShell) || !s.CanAccessCapability(ctx, u, target.ID, CapabilitySFTP) || !s.CanAccessCapability(ctx, u, target.ID, CapabilityForward) {
		t.Fatal("enabled capabilities were denied")
	}
	if s.CanAccessCapability(ctx, u, target.ID, CapabilitySCP) {
		t.Fatal("disabled SCP capability was allowed")
	}
	if s.ForwardAllowed(ctx, target.ID, "db.internal", 5432) {
		t.Fatal("unconfigured destination was allowed")
	}
	if err = s.AddForwardRule(ctx, "prod", "db.internal", 5432); err != nil {
		t.Fatal(err)
	}
	if !s.ForwardAllowed(ctx, target.ID, "DB.INTERNAL", 5432) || s.ForwardAllowed(ctx, target.ID, "db.internal", 5433) {
		t.Fatal("exact forwarding rule was not enforced")
	}
	rules, err := s.ListForwardRules(ctx)
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules=%#v err=%v", rules, err)
	}
}
func TestReusableSSHIdentityTargetAndDeletionSafety(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	identity, err := s.AddSSHIdentity(ctx, "deploy-key", "ssh-ed25519 AAAA", "SHA256:deploy")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetSSHIdentitySecret(ctx, identity.ID, []byte("nonce"), []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	target, err := s.AddTarget(ctx, NewTarget{Name: "stored", Host: "127.0.0.1", Port: 22, RemoteUsername: "root", CredentialKind: CredentialStoredKey, IdentityID: &identity.ID, HostKeyAlgorithm: "ssh-ed25519", HostPublicKey: "ssh-ed25519 AAAA"})
	if err != nil {
		t.Fatal(err)
	}
	if target.IdentityID == nil || *target.IdentityID != identity.ID || target.CredentialKind != CredentialStoredKey {
		t.Fatalf("stored-key target=%#v", target)
	}
	if err = s.DeleteSSHIdentity(ctx, identity.Name); err == nil {
		t.Fatal("deleted an SSH key that is still selected by a target")
	}
	if err = s.DeleteTarget(ctx, target.Name); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteSSHIdentity(ctx, identity.Name); err != nil {
		t.Fatal(err)
	}
}
func TestAuthorizationAndAdminInvariant(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	admin, err := s.AddUser(ctx, "admin", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AddGatewayKey(ctx, admin.Username, "SHA256:admin", "ssh-ed25519 AAAA", "main"); err != nil {
		t.Fatal(err)
	}
	member, err := s.AddUser(ctx, "alice", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AddGroup(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetGroupMember(ctx, "ops", "alice", true); err != nil {
		t.Fatal(err)
	}
	target, err := s.AddTarget(ctx, NewTarget{Name: "prod", Host: "127.0.0.1", Port: 22, RemoteUsername: "root", CredentialKind: CredentialPassword, HostKeyAlgorithm: "ssh-ed25519", HostPublicKey: "ssh-ed25519 AAAA"})
	if err != nil {
		t.Fatal(err)
	}
	if s.CanAccess(ctx, member, target.ID) {
		t.Fatal("ungranted member has access")
	}
	if err = s.SetGrant(ctx, "prod", "group", "ops", true); err != nil {
		t.Fatal(err)
	}
	if !s.CanAccess(ctx, member, target.ID) || !s.CanAccess(ctx, admin, target.ID) {
		t.Fatal("expected group/admin access")
	}
	if err = s.DeleteUser(ctx, "admin"); err == nil {
		t.Fatal("deleted final usable admin")
	}
}
func TestForeignKeysAndAudit(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	u, err := s.AddUser(ctx, "alice", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Audit(ctx, AuditEvent{ActorUserID: &u.ID, EventType: "test", Outcome: "success", Details: `{"safe":true}`}); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ActorUserID != nil {
		t.Fatalf("audit FK behavior: %#v", events)
	}
}
func TestGatewayKeyCanBeSharedAcrossUsersButNotDuplicatedPerUser(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	_, _ = s.AddUser(ctx, "alice", RoleMember)
	_, _ = s.AddUser(ctx, "bob", RoleMember)
	if err := s.AddGatewayKey(ctx, "alice", "SHA256:same", "key", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGatewayKey(ctx, "bob", "SHA256:same", "key", "b"); err != nil {
		t.Fatalf("shared key rejected for another username: %v", err)
	}
	if err := s.AddGatewayKey(ctx, "alice", "SHA256:same", "key", "duplicate"); err == nil {
		t.Fatal("duplicate key accepted for the same user")
	}
}
