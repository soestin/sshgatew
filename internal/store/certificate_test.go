package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestCertificateMappingsImportEditAndRemoval(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	alice, err := s.AddUser(ctx, "alice", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.AddUser(ctx, "bob", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	legacy := map[string]string{"web-alice": "alice"}
	if err = s.ImportCertificateUsernameMappings(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if u, err := s.UserForCertificateUsername(ctx, "web-alice"); err != nil || u.ID != alice.ID {
		t.Fatalf("imported user=%+v err=%v", u, err)
	}
	for _, alias := range []string{"bob", "alice", "bad+route", "UPPER", ""} {
		if err = s.SetCertificateUsernameMapping(ctx, alice.ID, alias); err == nil {
			t.Fatalf("accepted %q", alias)
		}
	}
	if err = s.SetCertificateUsernameMapping(ctx, bob.ID, "web-alice"); err == nil {
		t.Fatal("alias assigned to two users")
	}
	if _, err = s.AddUser(ctx, "web-alice", RoleMember); err == nil {
		t.Fatal("created user shadowing certificate alias")
	}
	if err = s.SetCertificateUsernameMapping(ctx, alice.ID, "new.alias"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UserForCertificateUsername(ctx, "web-alice"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old alias retained: %v", err)
	}
	if err = s.ImportCertificateUsernameMappings(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if alias, err := s.CertificateUsernameForUser(ctx, alice.ID); err != nil || alias != "new.alias" {
		t.Fatalf("edit overwritten: %q %v", alias, err)
	}
	if err = s.RemoveCertificateUsernameMapping(ctx, alice.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.ImportCertificateUsernameMappings(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UserForCertificateUsername(ctx, "web-alice"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("import restored removed mapping")
	}
	if err = s.SetCertificateUsernameMapping(ctx, alice.ID, "web-alice"); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UserForCertificateUsername(ctx, "web-alice"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("deleted user kept mapping")
	}
}
