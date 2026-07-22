package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func writePublicKey(t *testing.T, path string) gossh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, gossh.MarshalAuthorizedKey(s.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	return s.PublicKey()
}
func TestInitAndAdministrationCLI(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	adminKey := filepath.Join(dir, "admin.pub")
	writePublicKey(t, adminKey)
	var out, errOut bytes.Buffer
	if err := run([]string{"--config", cfg, "init", "--admin", "rootadmin", "--authorized-key", adminKey, "--data-dir", filepath.Join(dir, "data"), "--listen", "127.0.0.1:2222"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatalf("init: %v (%s)", err, errOut.String())
	}
	if err := run([]string{"--config", cfg, "users", "add", "alice"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config", cfg, "users", "add", "secondadmin", "--role", "admin"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config", cfg, "groups", "add", "ops"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config", cfg, "groups", "members", "add", "ops", "alice"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	hostKey := filepath.Join(dir, "host.pub")
	writePublicKey(t, hostKey)
	if err := run([]string{"--config", cfg, "targets", "add", "--name", "demo", "--host", "127.0.0.1", "--remote-user", "ubuntu", "--auth", "password", "--host-key-file", hostKey}, strings.NewReader("downstream-secret\n"), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "downstream-secret") {
		t.Fatal("secret leaked to output")
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, e := os.ReadFile(filepath.Join(dir, "data", "sshgatew.db") + suffix)
		if e == nil && bytes.Contains(b, []byte("downstream-secret")) {
			t.Fatalf("secret leaked into SQLite file %s", suffix)
		}
	}
	if err := run([]string{"--config", cfg, "grants", "add", "--target", "demo", "--group", "ops"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"--config", cfg, "targets", "list"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "demo") {
		t.Fatal("target missing from list")
	}
}
