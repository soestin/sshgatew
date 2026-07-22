package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCipherRoundTripAndBinding(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := Generate(p); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	n, ct, err := c.Encrypt(7, "password", Payload{Password: "super-secret"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Decrypt(7, "password", n, ct)
	if err != nil || got.Password != "super-secret" {
		t.Fatalf("round trip: %#v %v", got, err)
	}
	if _, err = c.Decrypt(8, "password", n, ct); err == nil {
		t.Fatal("target binding not enforced")
	}
	ct[0] ^= 1
	if _, err = c.Decrypt(7, "password", n, ct); err == nil {
		t.Fatal("tamper not detected")
	}
}
func TestPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := Generate(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected permission rejection")
	}
}
