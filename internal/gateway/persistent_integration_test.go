package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/config"
	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
)

type persistentFixture struct {
	server       *Server
	store        *store.Store
	clientConfig *gossh.ClientConfig
	users        map[string]store.User
	starts       atomic.Int32
	background   chan struct{}
}

func persistentGateway(t *testing.T, terminalLimit ...int) *persistentFixture {
	t.Helper()
	f := &persistentFixture{users: map[string]store.User{}, background: make(chan struct{})}
	address, hostKey := startProtocolTarget(t, func(ch gossh.Channel) {
		id := f.starts.Add(1)
		fmt.Fprintf(ch, "instance:%d ready\r\n", id)
		state := ""
		reader := bufio.NewReader(ch)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSuffix(line, "\n")
			switch {
			case line == "expect-escape":
				fmt.Fprint(ch, "waiting-for-escape\r\n")
				if key, err := reader.ReadByte(); err == nil && key == 27 {
					fmt.Fprint(ch, "escape-received\r\n")
				}
			case strings.HasPrefix(line, "set "):
				state = strings.TrimPrefix(line, "set ")
				fmt.Fprintf(ch, "stored:%s\r\n", state)
			case line == "show":
				fmt.Fprintf(ch, "state:%d:%s\r\n", id, state)
			case line == "background":
				fmt.Fprint(ch, "background-started\r\n")
				go func() { <-f.background; _, _ = io.WriteString(ch, "background-finished\r\n") }()
			case line == "screen":
				fmt.Fprint(ch, "\x1b[?1049h\x1b[2J\x1b[Heditor-screen\x1b[?25l\x1b[?2004h")
			case line == "normal":
				fmt.Fprint(ch, "\x1b[?1049l\x1b[?25h\x1b[?2004l")
			case line == "exit":
				return
			}
		}
	})
	cfg := config.ForDataDir(t.TempDir())
	cfg.ListenAddress = freeAddress(t)
	cfg.IdleTimeout = config.Duration(time.Minute)
	if len(terminalLimit) > 0 {
		cfg.MaxSessionsPerUser = terminalLimit[0]
	}
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
	f.store = st
	key := signer(t)
	for _, name := range []string{"alice", "bob"} {
		u, err := st.AddUser(context.Background(), name, store.RoleMember)
		if err != nil {
			t.Fatal(err)
		}
		f.users[name] = u
		if err := st.AddGatewayKey(context.Background(), name, gossh.FingerprintSHA256(key.PublicKey()), strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key.PublicKey()))), "test"); err != nil {
			t.Fatal(err)
		}
	}
	host, portText, _ := net.SplitHostPort(address)
	port, _ := net.LookupPort("tcp", portText)
	for _, name := range []string{"alpha", "beta"} {
		target, err := st.AddTarget(context.Background(), store.NewTarget{Name: name, Host: host, Port: port, RemoteUsername: "root", CredentialKind: store.CredentialPassword, HostKeyAlgorithm: hostKey.Type(), HostPublicKey: strings.TrimSpace(string(gossh.MarshalAuthorizedKey(hostKey)))})
		if err != nil {
			t.Fatal(err)
		}
		nonce, data, err := cipher.Encrypt(target.ID, store.CredentialPassword, secrets.Payload{Password: "downstream-secret"})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetTargetCredential(context.Background(), target.ID, nonce, data); err != nil {
			t.Fatal(err)
		}
		for name := range f.users {
			if err := st.SetGrantCapabilities(context.Background(), target.Name, "user", name, true, true, false, false, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.server, err = New(cfg, st, cipher, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = f.server.ListenAndServe() }()
	f.clientConfig = &gossh.ClientConfig{User: "alice", Auth: []gossh.AuthMethod{gossh.PublicKeys(key)}, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = f.server.Shutdown(ctx)
		_ = st.Close()
	})
	return f
}

type menuConnection struct {
	client  *gossh.Client
	session *gossh.Session
	input   io.WriteCloser
	output  lockedBuffer
}

func (f *persistentFixture) login(t *testing.T, name string) *menuConnection {
	t.Helper()
	cfg := *f.clientConfig
	cfg.User = name
	var client *gossh.Client
	var err error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		client, err = gossh.Dial("tcp", f.server.cfg.ListenAddress, &cfg)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	m := &menuConnection{client: client, session: session}
	if err := session.RequestPty("xterm-256color", 24, 100, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	m.input, err = session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	session.Stdout, session.Stderr = &m.output, &m.output
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	m.wait(t, 0, "Connection profiles")
	return m
}

func (m *menuConnection) wait(t *testing.T, offset int, text string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		out := m.output.String()
		if len(out) >= offset && strings.Contains(out[offset:], text) {
			return out[offset:]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("missing %q in new output: %q", text, m.output.String()[offset:])
	return ""
}
func (m *menuConnection) send(t *testing.T, keys, text string) string {
	t.Helper()
	offset := len(m.output.String())
	if _, err := io.WriteString(m.input, keys); err != nil {
		t.Fatal(err)
	}
	return m.wait(t, offset, text)
}

func TestPersistentTerminalSwitchReconnectAndIsolation(t *testing.T) {
	f := persistentGateway(t)
	a := f.login(t, "alice")
	a.send(t, "\r", "instance:1 ready")
	a.send(t, "set remembered\n", "stored:remembered")
	a.send(t, "background\n", "background-started")
	a.send(t, "\x1d", "Detached from alpha")
	close(f.background)
	a.send(t, "j\r", "instance:2 ready")
	a.send(t, "\x1d", "Detached from beta")
	a.send(t, "\r", "background-finished")
	a.send(t, "show\n", "state:1:remembered")
	// An abrupt client disconnect also detaches rather than closing the PTY.
	_ = a.client.Close()
	deadline := time.Now().Add(time.Second)
	for f.server.terminalStates(f.users["alice"].ID)[1] == "ATTACHED" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	a = f.login(t, "alice")
	a.send(t, "\r", "stored:remembered")
	a.send(t, "show\n", "state:1:remembered")
	// A second login cannot take over a terminal currently being controlled.
	other := f.login(t, "alice")
	other.send(t, "\r", "attached in another connection")
	if f.starts.Load() != 2 {
		t.Fatalf("resume created a new shell: %d", f.starts.Load())
	}
	b := f.login(t, "bob")
	b.send(t, "\r", "instance:3 ready")
	b.send(t, "show\n", "state:3:")
	if strings.Contains(b.output.String(), "remembered") {
		t.Fatal("another user saw Alice's terminal")
	}
	b.send(t, "\x1d", "Detached from alpha")
	// Exiting the gateway menu leaves both Alice and Bob's detached terminals.
	b.send(t, "q", "\x1b[?1049l")
	b = f.login(t, "bob")
	b.send(t, "\r", "instance:3 ready")
	b.send(t, "show\n", "state:3:")
	b.send(t, "\x1d", "Detached from alpha")
	a.send(t, "\x1d", "Detached from alpha")
	a.send(t, "x", "Close session")
	a.send(t, "y", "Session closed.")
	a.send(t, "\r", "instance:4 ready")
	a.send(t, "exit\n", "Disconnected from alpha")
	if f.starts.Load() != 4 {
		t.Fatalf("unexpected shell count %d", f.starts.Load())
	}
}

func TestPersistentTerminalLimitsAndShutdown(t *testing.T) {
	f := persistentGateway(t, 1)
	a := f.login(t, "alice")
	a.send(t, "\r", "instance:1 ready")
	a.send(t, "\x1d", "Detached from alpha")
	a.send(t, "j\r", "terminal limit reached")
	a.send(t, "\r", "instance:1 ready")
	if f.starts.Load() != 1 {
		t.Fatal("resuming at the session limit created another shell")
	}
	a.send(t, "\x1d", "Detached from alpha")
	_ = a.client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := f.server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.server.terminalStates(f.users["alice"].ID)) != 0 {
		t.Fatal("shutdown left a detached terminal running")
	}
}

func TestPersistentTerminalScreenRestoreAndRevocation(t *testing.T) {
	f := persistentGateway(t)
	a := f.login(t, "alice")
	a.send(t, "\r", "instance:1 ready")
	a.send(t, "expect-escape\n", "waiting-for-escape")
	a.send(t, "\x1b", "escape-received")
	a.send(t, "screen\n", "editor-screen")
	a.send(t, "\x1d", "Detached from alpha")
	output := a.send(t, "\r", "editor-screen")
	if !strings.Contains(output, "\x1b[?25l") || !strings.Contains(output, "\x1b[?2004h") {
		t.Fatal("terminal cursor/paste modes were not restored")
	}
	a.send(t, "normal\n", "instance:1 ready")
	a.send(t, "\x1d", "Detached from alpha")
	if err := f.store.SetGrantCapabilities(context.Background(), "alpha", "user", "alice", false, false, false, false, false); err != nil {
		t.Fatal(err)
	}
	a.send(t, "\r", "Access was revoked")
	deadline := time.Now().Add(7 * time.Second)
	for len(f.server.terminalStates(f.users["alice"].ID)) > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(f.server.terminalStates(f.users["alice"].ID)) != 0 {
		t.Fatal("revoked detached terminal stayed alive")
	}
}
