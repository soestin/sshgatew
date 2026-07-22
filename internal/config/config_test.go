package config

import (
	"os"
	"path/filepath"
	"testing"
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
