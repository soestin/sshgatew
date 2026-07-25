package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	want := ForDataDir(dir)
	want.ListenAddress = "127.0.0.1:2222"
	if err := Write(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenAddress != want.ListenAddress || got.DatabasePath != want.DatabasePath || got.IdleTimeout != want.IdleTimeout {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}
func TestUnknownFieldRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.toml")
	if err := os.WriteFile(p, []byte("listen_address=':2222'\nunknown=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected unknown-field error")
	}
}
func TestValidation(t *testing.T) {
	c := Default()
	c.MaxSessionsPerUser = c.MaxSessions + 1
	if err := c.Validate(); err == nil {
		t.Fatal("expected invalid limits")
	}
}

func TestOIDCValidationAndEnvironment(t *testing.T) {
	c := Default()
	c.OIDC.Enabled = true
	c.OIDC.IssuerURL = "http://identity.example.com"
	c.OIDC.ClientID = "sshgatew"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected insecure issuer rejection, got %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	base := Default()
	if err := Write(path, base); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHGATEW_OIDC_ENABLED", "true")
	t.Setenv("SSHGATEW_OIDC_ISSUER", "https://id.example.com/realms/team")
	t.Setenv("SSHGATEW_OIDC_CLIENT_ID", "sshgatew")
	t.Setenv("SSHGATEW_OIDC_CLIENT_SECRET", "not-rendered")
	t.Setenv("SSHGATEW_OIDC_USERNAME_CLAIM", "preferred_username")
	t.Setenv("SSHGATEW_OIDC_SCOPES", "openid,profile groups")
	t.Setenv("SSHGATEW_OIDC_LOGIN_TIMEOUT", "3m")
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.OIDC.Enabled || got.OIDC.ClientID != "sshgatew" || got.OIDC.ClientSecret != "not-rendered" ||
		got.OIDC.LoginTimeout != Duration(3*time.Minute) || strings.Join(got.OIDC.Scopes, ",") != "openid,profile,groups" {
		t.Fatalf("OIDC environment was not applied: %#v", got.OIDC)
	}
}

func TestEmptyOIDCEnvironmentDoesNotOverrideTOML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	want := Default()
	want.OIDC.Enabled = true
	want.OIDC.IssuerURL = "https://id.example.com"
	want.OIDC.ClientID = "sshgatew"
	if err := Write(path, want); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"SSHGATEW_OIDC_ENABLED", "SSHGATEW_OIDC_ISSUER", "SSHGATEW_OIDC_CLIENT_ID",
		"SSHGATEW_OIDC_CLIENT_SECRET", "SSHGATEW_OIDC_USERNAME_CLAIM",
		"SSHGATEW_OIDC_SCOPES", "SSHGATEW_OIDC_LOGIN_TIMEOUT",
	} {
		t.Setenv(name, "")
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.OIDC.Enabled || got.OIDC.IssuerURL != want.OIDC.IssuerURL || got.OIDC.ClientID != want.OIDC.ClientID {
		t.Fatalf("empty environment changed TOML configuration: %#v", got.OIDC)
	}
}
