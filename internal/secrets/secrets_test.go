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
func TestSSHIdentityCipherRoundTripAndNamespaceBinding(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := Generate(p); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := c.EncryptSSHIdentity(12, Payload{PrivateKey: []byte("private-material")})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.DecryptSSHIdentity(12, nonce, ciphertext)
	if err != nil || string(got.PrivateKey) != "private-material" {
		t.Fatalf("identity round trip: %#v %v", got, err)
	}
	if _, err = c.DecryptSSHIdentity(13, nonce, ciphertext); err == nil {
		t.Fatal("identity binding not enforced")
	}
	if _, err = c.Decrypt(12, CredentialKindForTest, nonce, ciphertext); err == nil {
		t.Fatal("identity ciphertext was accepted in target namespace")
	}
}

func TestTOTPCipherRoundTripAndBinding(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := Generate(p); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := c.EncryptTOTP(7, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := c.DecryptTOTP(7, nonce, ciphertext)
	if err != nil || secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	if _, err = c.DecryptTOTP(8, nonce, ciphertext); err == nil {
		t.Fatal("user binding not enforced")
	}
}

const CredentialKindForTest = "private_key"

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
