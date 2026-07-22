package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
			if !info.Mode().IsRegular() {
				return nil, errors.New("database must be a regular file")
			}
			return nil, fmt.Errorf("database permissions %04o are too open; require 0600", info.Mode().Perm())
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	dsn := path
	if path != ":memory:" {
		u := url.URL{Scheme: "file", Path: path}
		q := u.Query()
		q.Add("_pragma", "foreign_keys=1")
		q.Add("_pragma", "busy_timeout=5000")
		q.Add("_pragma", "journal_mode=WAL")
		u.RawQuery = q.Encode()
		dsn = u.String()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	for _, q := range []string{"PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000"} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite setup: %w", err)
		}
	}
	s := &Store{db: db}
	if path != ":memory:" {
		if err = os.Chmod(path, 0600); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) DB() *sql.DB  { return s.db }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE BINARY,
 role TEXT NOT NULL CHECK(role IN ('admin','member')), enabled INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS gateway_keys(
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 fingerprint TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS groups_table(
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE BINARY,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS group_members(
 group_id INTEGER NOT NULL REFERENCES groups_table(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(group_id,user_id));
CREATE TABLE IF NOT EXISTS targets(
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE BINARY, host TEXT NOT NULL,
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535), remote_username TEXT NOT NULL,
 credential_kind TEXT NOT NULL CHECK(credential_kind IN ('password','private_key')),
 credential_nonce BLOB, credential_ciphertext BLOB,
 host_key_algorithm TEXT NOT NULL, host_public_key TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS user_target_grants(
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, PRIMARY KEY(user_id,target_id));
CREATE TABLE IF NOT EXISTS group_target_grants(
 group_id INTEGER NOT NULL REFERENCES groups_table(id) ON DELETE CASCADE,
 target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, PRIMARY KEY(group_id,target_id));
CREATE TABLE IF NOT EXISTS audit_events(
 id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, claimed_username TEXT NOT NULL DEFAULT '',
 source_address TEXT NOT NULL DEFAULT '', event_type TEXT NOT NULL,
 target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('success','failure','denied')), details TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS audit_at_idx ON audit_events(at);
CREATE INDEX IF NOT EXISTS audit_actor_idx ON audit_events(actor_user_id);
CREATE INDEX IF NOT EXISTS audit_target_idx ON audit_events(target_id);
INSERT OR IGNORE INTO schema_migrations(version) VALUES(1);`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	var migrated int
	if err := s.db.QueryRow("SELECT count(*) FROM schema_migrations WHERE version=2").Scan(&migrated); err != nil {
		return err
	}
	if migrated != 0 {
		return nil
	}
	return s.migrateTargetsV2()
}

func (s *Store) migrateTargetsV2() error {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return err
	}
	defer conn.ExecContext(ctx, "PRAGMA foreign_keys=ON")
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	const migration = `
CREATE TABLE targets_v2(
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE BINARY, host TEXT NOT NULL,
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535), remote_username TEXT NOT NULL,
 credential_kind TEXT NOT NULL CHECK(credential_kind IN ('password','private_key','forwarded_agent')),
 credential_nonce BLOB, credential_ciphertext BLOB,
 host_key_algorithm TEXT NOT NULL, host_public_key TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO targets_v2 SELECT * FROM targets;
DROP TABLE targets;
ALTER TABLE targets_v2 RENAME TO targets;
INSERT INTO schema_migrations(version) VALUES(2);`
	if _, err = tx.ExecContext(ctx, migration); err != nil {
		return fmt.Errorf("migrate targets for forwarded agents: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	var violations string
	if err = conn.QueryRowContext(ctx, `SELECT coalesce(group_concat("table" || ':' || rowid), '') FROM pragma_foreign_key_check`).Scan(&violations); err != nil {
		return err
	}
	if violations != "" {
		return fmt.Errorf("foreign key check failed after migration: %s", violations)
	}
	return nil
}

func validateName(v, kind string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if !nameRE.MatchString(v) {
		return "", fmt.Errorf("%s must match %s", kind, nameRE.String())
	}
	return v, nil
}
func ValidateUsername(v string) error { _, err := validateName(v, "username"); return err }
func validRole(role string) bool      { return role == RoleAdmin || role == RoleMember }

func (s *Store) AddUser(ctx context.Context, username, role string) (User, error) {
	username, err := validateName(username, "username")
	if err != nil {
		return User{}, err
	}
	if !validRole(role) {
		return User{}, errors.New("role must be admin or member")
	}
	r, err := s.db.ExecContext(ctx, "INSERT INTO users(username,role) VALUES(?,?)", username, role)
	if err != nil {
		return User{}, err
	}
	id, _ := r.LastInsertId()
	return s.UserByID(ctx, id)
}
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT id,username,role,enabled,created_at FROM users WHERE id=?", id))
}
func (s *Store) UserByName(ctx context.Context, name string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT id,username,role,enabled,created_at FROM users WHERE username=?", strings.ToLower(name)))
}
func scanUser(row *sql.Row) (User, error) {
	var u User
	var at string
	err := row.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &at)
	u.CreatedAt = parseTime(at)
	return u, err
}
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,username,role,enabled,created_at FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var at string
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &at); err != nil {
			return nil, err
		}
		u.CreatedAt = parseTime(at)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) SetUserEnabled(ctx context.Context, name string, enabled bool) error {
	u, err := s.UserByName(ctx, name)
	if err != nil {
		return err
	}
	if !enabled && u.Role == RoleAdmin {
		if err = s.ensureOtherUsableAdmin(ctx, u.ID); err != nil {
			return err
		}
	}
	r, err := s.db.ExecContext(ctx, "UPDATE users SET enabled=? WHERE id=?", enabled, u.ID)
	return changed(r, err)
}
func (s *Store) SetUserRole(ctx context.Context, name, role string) error {
	if !validRole(role) {
		return errors.New("role must be admin or member")
	}
	u, err := s.UserByName(ctx, name)
	if err != nil {
		return err
	}
	if u.Role == RoleAdmin && role != RoleAdmin {
		if err = s.ensureOtherUsableAdmin(ctx, u.ID); err != nil {
			return err
		}
	}
	r, err := s.db.ExecContext(ctx, "UPDATE users SET role=? WHERE id=?", role, u.ID)
	return changed(r, err)
}
func (s *Store) DeleteUser(ctx context.Context, name string) error {
	u, err := s.UserByName(ctx, name)
	if err != nil {
		return err
	}
	if u.Role == RoleAdmin {
		if err = s.ensureOtherUsableAdmin(ctx, u.ID); err != nil {
			return err
		}
	}
	r, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id=?", u.ID)
	return changed(r, err)
}
func (s *Store) ensureOtherUsableAdmin(ctx context.Context, exclude int64) error {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(DISTINCT u.id) FROM users u JOIN gateway_keys k ON k.user_id=u.id WHERE u.role='admin' AND u.enabled=1 AND u.id<>?`, exclude).Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("operation would remove the final usable administrator")
	}
	return nil
}

func (s *Store) AddGatewayKey(ctx context.Context, username, fingerprint, publicKey, label string) error {
	u, err := s.UserByName(ctx, username)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO gateway_keys(user_id,fingerprint,public_key,label) VALUES(?,?,?,?)", u.ID, fingerprint, publicKey, label)
	return err
}
func (s *Store) ListGatewayKeys(ctx context.Context, username string) ([]GatewayKey, error) {
	u, err := s.UserByName(ctx, username)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,user_id,fingerprint,public_key,label,created_at FROM gateway_keys WHERE user_id=? ORDER BY id", u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GatewayKey
	for rows.Next() {
		var k GatewayKey
		var at string
		if err = rows.Scan(&k.ID, &k.UserID, &k.Fingerprint, &k.PublicKey, &k.Label, &at); err != nil {
			return nil, err
		}
		k.CreatedAt = parseTime(at)
		out = append(out, k)
	}
	return out, rows.Err()
}
func (s *Store) RemoveGatewayKey(ctx context.Context, username, fingerprint string) error {
	u, err := s.UserByName(ctx, username)
	if err != nil {
		return err
	}
	var count int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM gateway_keys WHERE user_id=?", u.ID).Scan(&count); err != nil {
		return err
	}
	if u.Role == RoleAdmin && u.Enabled && count <= 1 {
		if err = s.ensureOtherUsableAdmin(ctx, u.ID); err != nil {
			return err
		}
	}
	r, err := s.db.ExecContext(ctx, "DELETE FROM gateway_keys WHERE user_id=? AND fingerprint=?", u.ID, fingerprint)
	return changed(r, err)
}
func (s *Store) AuthenticateKey(ctx context.Context, username, fingerprint string) (User, error) {
	var u User
	var at string
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.role,u.enabled,u.created_at FROM users u JOIN gateway_keys k ON k.user_id=u.id WHERE u.username=? AND u.enabled=1 AND k.fingerprint=?`, strings.ToLower(username), fingerprint).Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &at)
	u.CreatedAt = parseTime(at)
	return u, err
}

func (s *Store) AddGroup(ctx context.Context, name string) error {
	name, err := validateName(name, "group")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO groups_table(name) VALUES(?)", name)
	return err
}
func (s *Store) DeleteGroup(ctx context.Context, name string) error {
	r, err := s.db.ExecContext(ctx, "DELETE FROM groups_table WHERE name=?", strings.ToLower(name))
	return changed(r, err)
}
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,created_at FROM groups_table ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		var at string
		if err = rows.Scan(&g.ID, &g.Name, &at); err != nil {
			return nil, err
		}
		g.CreatedAt = parseTime(at)
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) SetGroupMember(ctx context.Context, group, username string, add bool) error {
	u, err := s.UserByName(ctx, username)
	if err != nil {
		return err
	}
	var gid int64
	if err = s.db.QueryRowContext(ctx, "SELECT id FROM groups_table WHERE name=?", strings.ToLower(group)).Scan(&gid); err != nil {
		return err
	}
	if add {
		_, err = s.db.ExecContext(ctx, "INSERT OR IGNORE INTO group_members(group_id,user_id) VALUES(?,?)", gid, u.ID)
	} else {
		_, err = s.db.ExecContext(ctx, "DELETE FROM group_members WHERE group_id=? AND user_id=?", gid, u.ID)
	}
	return err
}
func (s *Store) ListGroupMembers(ctx context.Context) ([]GroupMember, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.name,u.username FROM group_members gm JOIN groups_table g ON g.id=gm.group_id JOIN users u ON u.id=gm.user_id ORDER BY g.name,u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMember
	for rows.Next() {
		var v GroupMember
		if err = rows.Scan(&v.Group, &v.Username); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type NewTarget struct {
	Name, Host                                                      string
	Port                                                            int
	RemoteUsername, CredentialKind, HostKeyAlgorithm, HostPublicKey string
}

func (s *Store) AddTarget(ctx context.Context, n NewTarget) (Target, error) {
	if strings.TrimSpace(n.Name) == "" || strings.TrimSpace(n.Host) == "" || strings.TrimSpace(n.RemoteUsername) == "" {
		return Target{}, errors.New("target name, host, and remote username are required")
	}
	if n.Port < 1 || n.Port > 65535 {
		return Target{}, errors.New("port must be between 1 and 65535")
	}
	if !validCredentialKind(n.CredentialKind) {
		return Target{}, errors.New("invalid credential kind")
	}
	if n.HostKeyAlgorithm == "" || n.HostPublicKey == "" {
		return Target{}, errors.New("pinned host key is required")
	}
	r, err := s.db.ExecContext(ctx, `INSERT INTO targets(name,host,port,remote_username,credential_kind,host_key_algorithm,host_public_key) VALUES(?,?,?,?,?,?,?)`, n.Name, n.Host, n.Port, n.RemoteUsername, n.CredentialKind, n.HostKeyAlgorithm, n.HostPublicKey)
	if err != nil {
		return Target{}, err
	}
	id, _ := r.LastInsertId()
	return s.TargetByID(ctx, id)
}
func targetCols() string {
	return "id,name,host,port,remote_username,credential_kind,enabled,host_key_algorithm,host_public_key,credential_nonce,credential_ciphertext,created_at,updated_at"
}

type scanner interface{ Scan(...any) error }

func scanTarget(r scanner) (Target, error) {
	var t Target
	var ca, ua string
	err := r.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.RemoteUsername, &t.CredentialKind, &t.Enabled, &t.HostKeyAlgorithm, &t.HostPublicKey, &t.Nonce, &t.Ciphertext, &ca, &ua)
	t.CreatedAt = parseTime(ca)
	t.UpdatedAt = parseTime(ua)
	return t, err
}
func (s *Store) TargetByID(ctx context.Context, id int64) (Target, error) {
	return scanTarget(s.db.QueryRowContext(ctx, "SELECT "+targetCols()+" FROM targets WHERE id=?", id))
}
func (s *Store) TargetByName(ctx context.Context, name string) (Target, error) {
	return scanTarget(s.db.QueryRowContext(ctx, "SELECT "+targetCols()+" FROM targets WHERE name=?", name))
}
func (s *Store) ListTargets(ctx context.Context) ([]Target, error) {
	return s.listTargets(ctx, "SELECT "+targetCols()+" FROM targets ORDER BY name")
}
func (s *Store) ListAuthorizedTargets(ctx context.Context, u User) ([]Target, error) {
	if u.Role == RoleAdmin {
		return s.listTargets(ctx, "SELECT "+targetCols()+" FROM targets WHERE enabled=1 ORDER BY name")
	}
	return s.listTargets(ctx, `SELECT DISTINCT `+targetColsPrefixed("t")+` FROM targets t LEFT JOIN user_target_grants ug ON ug.target_id=t.id AND ug.user_id=? LEFT JOIN group_target_grants gg ON gg.target_id=t.id LEFT JOIN group_members gm ON gm.group_id=gg.group_id AND gm.user_id=? WHERE t.enabled=1 AND (ug.user_id IS NOT NULL OR gm.user_id IS NOT NULL) ORDER BY t.name`, u.ID, u.ID)
}
func targetColsPrefixed(p string) string {
	parts := strings.Split(targetCols(), ",")
	for i := range parts {
		parts[i] = p + "." + parts[i]
	}
	return strings.Join(parts, ",")
}
func (s *Store) listTargets(ctx context.Context, q string, args ...any) ([]Target, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (s *Store) SetTargetEnabled(ctx context.Context, name string, enabled bool) error {
	r, err := s.db.ExecContext(ctx, "UPDATE targets SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE name=?", enabled, name)
	return changed(r, err)
}
func (s *Store) DeleteTarget(ctx context.Context, name string) error {
	r, err := s.db.ExecContext(ctx, "DELETE FROM targets WHERE name=?", name)
	return changed(r, err)
}
func (s *Store) SetTargetCredential(ctx context.Context, id int64, nonce, ciphertext []byte) error {
	r, err := s.db.ExecContext(ctx, "UPDATE targets SET credential_nonce=?,credential_ciphertext=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", nonce, ciphertext, id)
	return changed(r, err)
}
func (s *Store) SetTargetCredentialKind(ctx context.Context, id int64, kind string, nonce, ciphertext []byte) error {
	if !validCredentialKind(kind) {
		return errors.New("invalid credential kind")
	}
	r, err := s.db.ExecContext(ctx, "UPDATE targets SET credential_kind=?,credential_nonce=?,credential_ciphertext=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", kind, nonce, ciphertext, id)
	return changed(r, err)
}

func validCredentialKind(kind string) bool {
	return kind == CredentialPassword || kind == CredentialPrivateKey || kind == CredentialAgent
}
func (s *Store) SetTargetHostKey(ctx context.Context, name, algorithm, publicKey string) error {
	r, err := s.db.ExecContext(ctx, "UPDATE targets SET host_key_algorithm=?,host_public_key=?,updated_at=CURRENT_TIMESTAMP WHERE name=?", algorithm, publicKey, name)
	return changed(r, err)
}
func (s *Store) UpdateTarget(ctx context.Context, name, host string, port int, remoteUser string) error {
	if host == "" || remoteUser == "" || port < 1 || port > 65535 {
		return errors.New("invalid target fields")
	}
	r, err := s.db.ExecContext(ctx, "UPDATE targets SET host=?,port=?,remote_username=?,updated_at=CURRENT_TIMESTAMP WHERE name=?", host, port, remoteUser, name)
	return changed(r, err)
}

func (s *Store) SetGrant(ctx context.Context, target, kind, principal string, add bool) error {
	t, err := s.TargetByName(ctx, target)
	if err != nil {
		return err
	}
	var table, col string
	var id int64
	if kind == "user" {
		u, e := s.UserByName(ctx, principal)
		if e != nil {
			return e
		}
		id = u.ID
		table = "user_target_grants"
		col = "user_id"
	} else if kind == "group" {
		if e := s.db.QueryRowContext(ctx, "SELECT id FROM groups_table WHERE name=?", strings.ToLower(principal)).Scan(&id); e != nil {
			return e
		}
		table = "group_target_grants"
		col = "group_id"
	} else {
		return errors.New("principal kind must be user or group")
	}
	if add {
		_, err = s.db.ExecContext(ctx, "INSERT OR IGNORE INTO "+table+"("+col+",target_id) VALUES(?,?)", id, t.ID)
	} else {
		_, err = s.db.ExecContext(ctx, "DELETE FROM "+table+" WHERE "+col+"=? AND target_id=?", id, t.ID)
	}
	return err
}
func (s *Store) ListGrants(ctx context.Context) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT t.name,'user',u.username FROM user_target_grants x JOIN users u ON u.id=x.user_id JOIN targets t ON t.id=x.target_id UNION ALL SELECT t.name,'group',g.name FROM group_target_grants x JOIN groups_table g ON g.id=x.group_id JOIN targets t ON t.id=x.target_id ORDER BY 1,2,3`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err = rows.Scan(&g.Target, &g.Kind, &g.Principal); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) CanAccess(ctx context.Context, u User, targetID int64) bool {
	if !u.Enabled {
		return false
	}
	var n int
	if u.Role == RoleAdmin {
		_ = s.db.QueryRowContext(ctx, "SELECT count(*) FROM targets WHERE id=? AND enabled=1", targetID).Scan(&n)
	} else {
		_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM targets t WHERE t.id=? AND t.enabled=1 AND (EXISTS(SELECT 1 FROM user_target_grants WHERE user_id=? AND target_id=t.id) OR EXISTS(SELECT 1 FROM group_members gm JOIN group_target_grants gg ON gg.group_id=gm.group_id WHERE gm.user_id=? AND gg.target_id=t.id))`, targetID, u.ID, u.ID).Scan(&n)
	}
	return n > 0
}

func (s *Store) Audit(ctx context.Context, e AuditEvent) error {
	if e.Outcome == "" {
		e.Outcome = "success"
	}
	if e.Details == "" {
		e.Details = "{}"
	}
	var safe map[string]any
	if json.Unmarshal([]byte(e.Details), &safe) != nil {
		return errors.New("audit details must be valid JSON")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,claimed_username,source_address,event_type,target_id,outcome,details) VALUES(?,?,?,?,?,?,?)`, e.ActorUserID, e.ClaimedUsername, e.SourceAddress, e.EventType, e.TargetID, e.Outcome, e.Details)
	return err
}
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,at,actor_user_id,claimed_username,source_address,event_type,target_id,outcome,details FROM audit_events ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var at string
		if err = rows.Scan(&e.ID, &at, &e.ActorUserID, &e.ClaimedUsername, &e.SourceAddress, &e.EventType, &e.TargetID, &e.Outcome, &e.Details); err != nil {
			return nil, err
		}
		e.At = parseTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
func (s *Store) PruneAudit(ctx context.Context, before time.Time) (int64, error) {
	r, err := s.db.ExecContext(ctx, "DELETE FROM audit_events WHERE at < ?", before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func changed(r sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
func parseTime(v string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if t, e := time.Parse(layout, v); e == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
