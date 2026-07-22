package downstream

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
)

func TestParseHostKeyAndAuthMethods(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	got, err := ParseHostKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if gossh.FingerprintSHA256(got) != gossh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatal("fingerprint mismatch")
	}
	if _, err = authMethod(store.CredentialPassword, secrets.Payload{Password: "x"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = authMethod(store.CredentialPassword, secrets.Payload{}, nil); err == nil {
		t.Fatal("empty password accepted")
	}
	block, err := gossh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authMethod(store.CredentialPrivateKey, secrets.Payload{PrivateKey: pem.EncodeToMemory(block)}, nil); err != nil {
		t.Fatal(err)
	}
	enc, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte("passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authMethod(store.CredentialPrivateKey, secrets.Payload{PrivateKey: pem.EncodeToMemory(enc), Passphrase: "passphrase"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestForwardedAgentIsRestrictedToConfiguredKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err = keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	connection := &AgentConnection{Agent: keyring, closer: io.NopCloser(strings.NewReader(""))}
	payload := secrets.Payload{PublicKey: gossh.MarshalAuthorizedKey(mustPublicKey(t, publicKey))}
	if _, err = authMethod(store.CredentialAgent, payload, nil); err == nil || !strings.Contains(err.Error(), "ssh -A") {
		t.Fatalf("missing-agent error was not actionable: %v", err)
	}
	if _, err = authMethod(store.CredentialAgent, payload, connection); err != nil {
		t.Fatal(err)
	}

	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload.PublicKey = gossh.MarshalAuthorizedKey(mustPublicKey(t, otherPublic))
	if _, err = authMethod(store.CredentialAgent, payload, connection); err == nil || !strings.Contains(err.Error(), "does not contain required key") {
		t.Fatalf("unexpected mismatch result: %v", err)
	}
}

func mustPublicKey(t *testing.T, key any) gossh.PublicKey {
	t.Helper()
	publicKey, err := gossh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}
