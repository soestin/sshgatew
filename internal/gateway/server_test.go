package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/config"
	"sshgatew/internal/oidcdevice"
	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
	"sshgatew/internal/totp"
)

func signer(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func writeHostKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
}
func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

type fakeOIDCAuthenticator struct {
	identity oidcdevice.Identity
	begins   int
}

func (f *fakeOIDCAuthenticator) Begin(context.Context) (oidcdevice.Login, error) {
	f.begins++
	return oidcdevice.Login{UserCode: "ABCD-1234", VerificationURI: "https://id.example.com/activate", VerificationURIComplete: "https://id.example.com/activate?code=ABCD-1234"}, nil
}

func (f *fakeOIDCAuthenticator) Complete(context.Context, oidcdevice.Login) (oidcdevice.Identity, error) {
	return f.identity, nil
}

func TestPublicKeyLoginAndInteractiveTUI(t *testing.T) {
	dir := t.TempDir()
	cfg := config.ForDataDir(dir)
	cfg.ListenAddress = freeAddress(t)
	cfg.IdleTimeout = config.Duration(time.Minute)
	writeHostKey(t, cfg.HostKeyPath)
	if err := secrets.Generate(cfg.MasterKeyPath); err != nil {
		t.Fatal(err)
	}
	cipher, err := secrets.Load(cfg.MasterKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	clientSigner := signer(t)
	u, err := st.AddUser(context.Background(), "alice", store.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.AddGatewayKey(context.Background(), u.Username, gossh.FingerprintSHA256(clientSigner.PublicKey()), strings.TrimSpace(string(gossh.MarshalAuthorizedKey(clientSigner.PublicKey()))), "test"); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, cipher, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	clientCfg := &gossh.ClientConfig{User: "alice", Auth: []gossh.AuthMethod{gossh.PublicKeys(clientSigner)}, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second}
	var client *gossh.Client
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		client, err = gossh.Dial("tcp", cfg.ListenAddress, clientCfg)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err = sess.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output lockedBuffer
	sess.Stdout = &output
	sess.Stderr = &output
	if err = sess.Shell(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	_, _ = io.WriteString(stdin, "q")
	wait := make(chan error, 1)
	go func() { wait <- sess.Wait() }()
	select {
	case err = <-wait:
		if err != nil {
			t.Fatalf("session failed: %v output=%q", err, output.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("TUI did not exit; output=%q", output.String())
	}
	if !strings.Contains(output.String(), "SSHGateW") {
		t.Fatalf("missing TUI output: %q", output.String())
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := cipher.EncryptTOTP(u.ID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.SetUserTOTP(context.Background(), u.ID, nonce, ciphertext); err != nil {
		t.Fatal(err)
	}
	code, _, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	totpClientCfg := &gossh.ClientConfig{User: "alice", Auth: []gossh.AuthMethod{gossh.PublicKeys(clientSigner), gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = code
		}
		return answers, nil
	})}, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second}
	client, err = gossh.Dial("tcp", cfg.ListenAddress, totpClientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	totpSession, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err = totpSession.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	totpInput, err := totpSession.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var totpOutput lockedBuffer
	totpSession.Stdout, totpSession.Stderr = &totpOutput, &totpOutput
	if err = totpSession.Shell(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	_, _ = io.WriteString(totpInput, "q")
	if err = totpSession.Wait(); err != nil {
		t.Fatal(err)
	}
	if got := totpOutput.String(); !strings.Contains(got, "Connection profiles") {
		t.Fatalf("TOTP login did not reach the main TUI: %q", got)
	}
	badCfg := &gossh.ClientConfig{User: "alice", Auth: []gossh.AuthMethod{gossh.PublicKeys(signer(t))}, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second}
	if bad, err := gossh.Dial("tcp", cfg.ListenAddress, badCfg); err == nil {
		bad.Close()
		t.Fatal("unregistered key authenticated")
	}
	_ = client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-serveErr:
		if err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "Server closed") {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestOIDCKeyboardInteractiveLoginPreservesTOTPPolicy(t *testing.T) {
	dir := t.TempDir()
	cfg := config.ForDataDir(dir)
	cfg.ListenAddress = freeAddress(t)
	cfg.IdleTimeout = config.Duration(time.Minute)
	cfg.OIDC.IssuerURL = "https://id.example.com/application/o/gateway/"
	writeHostKey(t, cfg.HostKeyPath)
	if err := secrets.Generate(cfg.MasterKeyPath); err != nil {
		t.Fatal(err)
	}
	cipher, err := secrets.Load(cfg.MasterKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.AddUser(context.Background(), "alice", store.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := cipher.EncryptTOTP(u.ID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.SetUserTOTP(context.Background(), u.ID, nonce, ciphertext); err != nil {
		t.Fatal(err)
	}
	code, _, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, cipher, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeOIDCAuthenticator{identity: oidcdevice.Identity{Subject: "subject-123", Username: "alice"}}
	srv.oidc = fake
	if err = st.LinkOIDCIdentity(context.Background(), u.ID, cfg.OIDC.IssuerURL, fake.identity.Subject, fake.identity.Username); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	var sawOIDC, sawTOTP bool
	clientConfig := &gossh.ClientConfig{
		User: "alice",
		Auth: []gossh.AuthMethod{gossh.KeyboardInteractive(func(name, instruction string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			switch {
			case strings.Contains(name, "OIDC"):
				sawOIDC = strings.Contains(instruction, "https://id.example.com/activate") && strings.Contains(instruction, "ABCD-1234")
			case strings.Contains(name, "two-factor"):
				sawTOTP = true
				for i := range answers {
					answers[i] = code
				}
			}
			return answers, nil
		})},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	}
	var client *gossh.Client
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		client, err = gossh.Dial("tcp", cfg.ListenAddress, clientConfig)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("OIDC SSH handshake failed: %v (oidc=%v totp=%v begins=%d)", err, sawOIDC, sawTOTP, fake.begins)
	}
	if !sawOIDC || !sawTOTP || fake.begins != 1 {
		t.Fatalf("incomplete OIDC/TOTP flow: oidc=%v totp=%v begins=%d", sawOIDC, sawTOTP, fake.begins)
	}
	client.Close()

	fake.identity = oidcdevice.Identity{Subject: "unlinked-subject", Username: "bob"}
	beginsBeforeFailure := fake.begins
	if bad, dialErr := gossh.Dial("tcp", cfg.ListenAddress, clientConfig); dialErr == nil {
		bad.Close()
		t.Fatal("OIDC identity for a different username authenticated")
	}
	if fake.begins != beginsBeforeFailure+1 {
		t.Fatalf("failed OIDC login retried %d times in one SSH connection", fake.begins-beginsBeforeFailure)
	}
}
