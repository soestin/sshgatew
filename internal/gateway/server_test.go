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
