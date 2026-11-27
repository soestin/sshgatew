package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
)

var certificateUsernameRE = regexp.MustCompile(`^[a-z0-9_.-]{1,128}$`)

// Certificate mappings are explicit, administrator-managed identities. They do
// not create users and are only consulted after certificate validation.
func (s *Store) SetCertificateUsernameMapping(ctx context.Context, userID int64, alias string) error {
	alias = strings.TrimSpace(alias)
	if !certificateUsernameRE.MatchString(alias) {
		return errors.New("certificate username must be 1–128 lowercase letters, digits, dots, underscores or hyphens")
	}
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if alias == u.Username {
		return errors.New("certificate username already matches the account; no mapping is needed")
	}
	existing, err := s.UserByName(ctx, alias)
	if err == nil && existing.ID != userID {
		return errors.New("certificate username belongs to an existing account")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO certificate_username_mappings(user_id,certificate_username) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET certificate_username=excluded.certificate_username`, userID, alias)
	return err
}

func (s *Store) CertificateUsernameForUser(ctx context.Context, userID int64) (string, error) {
	var alias string
	err := s.db.QueryRowContext(ctx, `SELECT certificate_username FROM certificate_username_mappings WHERE user_id=?`, userID).Scan(&alias)
	return alias, err
}

func (s *Store) UserForCertificateUsername(ctx context.Context, alias string) (User, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM certificate_username_mappings WHERE certificate_username=?`, alias).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return s.UserByName(ctx, alias)
	}
	if err != nil {
		return User{}, err
	}
	return s.UserByID(ctx, id)
}

func (s *Store) RemoveCertificateUsernameMapping(ctx context.Context, userID int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM certificate_username_mappings WHERE user_id=?`, userID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// Import legacy TOML mappings once. Later in-app edits/removals survive restarts,
// even while the old configuration remains mounted.
func (s *Store) ImportCertificateUsernameMappings(ctx context.Context, aliases map[string]string) error {
	if len(aliases) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var imported int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM certificate_mapping_imports`).Scan(&imported); err != nil {
		return err
	}
	if imported != 0 {
		return nil
	}
	for alias, username := range aliases {
		if !certificateUsernameRE.MatchString(alias) {
			return errors.New("invalid legacy certificate username")
		}
		var id int64
		if err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE username=?`, username).Scan(&id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO certificate_username_mappings(user_id,certificate_username) VALUES(?,?)`, id, alias); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO certificate_mapping_imports(id) VALUES(1)`); err != nil {
		return err
	}
	return tx.Commit()
}
