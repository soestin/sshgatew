package downstream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	charmssh "github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
)

type fakeSession struct {
	input   *bytes.Reader
	output  bytes.Buffer
	windows chan charmssh.Window
}

func newFakeSession() *fakeSession {
	return &fakeSession{input: bytes.NewReader(nil), windows: make(chan charmssh.Window, 2)}
}
func (f *fakeSession) Read(p []byte) (int, error)                     { return f.input.Read(p) }
func (f *fakeSession) Write(p []byte) (int, error)                    { return f.output.Write(p) }
func (f *fakeSession) Close() error                                   { return nil }
func (f *fakeSession) CloseWrite() error                              { return nil }
func (f *fakeSession) SendRequest(string, bool, []byte) (bool, error) { return false, nil }
func (f *fakeSession) Stderr() io.ReadWriter                          { return &f.output }
func (f *fakeSession) User() string                                   { return "gateway-user" }
func (f *fakeSession) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
}
func (f *fakeSession) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
}
func (f *fakeSession) Environ() []string                 { return nil }
func (f *fakeSession) Exit(int) error                    { return nil }
func (f *fakeSession) Command() []string                 { return nil }
func (f *fakeSession) RawCommand() string                { return "" }
func (f *fakeSession) Subsystem() string                 { return "" }
func (f *fakeSession) PublicKey() charmssh.PublicKey     { return nil }
func (f *fakeSession) Context() charmssh.Context         { return nil }
func (f *fakeSession) Permissions() charmssh.Permissions { return charmssh.Permissions{} }
func (f *fakeSession) EmulatedPty() bool                 { return true }
func (f *fakeSession) Pty() (charmssh.Pty, <-chan charmssh.Window, bool) {
	return charmssh.Pty{Term: "xterm-256color", Window: charmssh.Window{Width: 80, Height: 24}}, f.windows, true
}
func (f *fakeSession) Signals(chan<- charmssh.Signal) {}
func (f *fakeSession) Break(chan<- bool)              {}

type testSSHServer struct {
	address   string
	host      gossh.Signer
	authCalls atomic.Int32
	resize    chan struct{}
	close     func()
}

type trackingCloser struct{ closed atomic.Bool }

func (c *trackingCloser) Close() error {
	c.closed.Store(true)
	return nil
}

func startPasswordServer(t *testing.T) *testSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSSHServer{address: l.Addr().String(), host: host, resize: make(chan struct{}, 1), close: func() { _ = l.Close() }}
	cfg := &gossh.ServerConfig{PasswordCallback: func(_ gossh.ConnMetadata, p []byte) (*gossh.Permissions, error) {
		s.authCalls.Add(1)
		if string(p) != "correct-password" {
			return nil, errors.New("denied")
		}
		return nil, nil
	}}
	cfg.AddHostKey(host)
	go func() {
		for {
			raw, e := l.Accept()
			if e != nil {
				return
			}
			go serveTestSSH(raw, cfg, s.resize)
		}
	}()
	t.Cleanup(s.close)
	return s
}

func startPublicKeyServer(t *testing.T, authorized gossh.PublicKey) *testSSHServer {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := gossh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testSSHServer{address: listener.Addr().String(), host: host, resize: make(chan struct{}, 1), close: func() { _ = listener.Close() }}
	config := &gossh.ServerConfig{PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		server.authCalls.Add(1)
		if key.Type() != authorized.Type() || !bytes.Equal(key.Marshal(), authorized.Marshal()) {
			return nil, errors.New("denied")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	go func() {
		for {
			raw, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveTestSSH(raw, config, server.resize)
		}
	}()
	t.Cleanup(server.close)
	return server
}
func serveTestSSH(raw net.Conn, cfg *gossh.ServerConfig, resize chan struct{}) {
	defer raw.Close()
	_, chans, reqs, err := gossh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	go gossh.DiscardRequests(reqs)
	for incoming := range chans {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(gossh.UnknownChannelType, "session only")
			continue
		}
		ch, requests, e := incoming.Accept()
		if e != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range requests {
				switch r.Type {
				case "pty-req":
					_ = r.Reply(true, nil)
				case "window-change":
					select {
					case resize <- struct{}{}:
					default:
					}
				case "shell":
					_ = r.Reply(true, nil)
					_, _ = ch.Write([]byte("downstream-ready\r\n"))
					go func() {
						select {
						case <-resize:
						case <-time.After(time.Second):
						}
						_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
						_ = ch.Close()
					}()
				default:
					_ = r.Reply(false, nil)
				}
			}
		}()
	}
}
func targetFor(s *testSSHServer, key gossh.PublicKey) store.Target {
	host, port, _ := net.SplitHostPort(s.address)
	p, _ := net.LookupPort("tcp", port)
	return store.Target{ID: 1, Name: "test", Host: host, Port: p, RemoteUsername: "remote", CredentialKind: store.CredentialPassword, HostKeyAlgorithm: key.Type(), HostPublicKey: strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key))), Enabled: true}
}
func TestConnectPasswordPinnedHostAndResize(t *testing.T) {
	srv := startPasswordServer(t)
	in := newFakeSession()
	in.windows <- charmssh.Window{Width: 120, Height: 40}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := Connector{Timeout: time.Second}.Connect(ctx, in, in.windows, targetFor(srv, srv.host.PublicKey()), secrets.Payload{Password: "correct-password"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(in.output.String(), "downstream-ready") {
		t.Fatalf("missing output: %q", in.output.String())
	}
	if srv.authCalls.Load() != 1 {
		t.Fatalf("auth calls=%d", srv.authCalls.Load())
	}
}
func TestHostMismatchPreventsAuthentication(t *testing.T) {
	srv := startPasswordServer(t)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _ := gossh.NewSignerFromKey(wrongPriv)
	in := newFakeSession()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := Connector{Timeout: time.Second}.Connect(ctx, in, in.windows, targetFor(srv, wrong.PublicKey()), secrets.Payload{Password: "correct-password"}, nil)
	if err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
	if srv.authCalls.Load() != 0 {
		t.Fatal("credential authentication reached mismatched host")
	}
}

func TestConnectWithRestrictedForwardedAgent(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	server := startPublicKeyServer(t, authorized)
	keyring := agent.NewKeyring()
	if err = keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	target := targetFor(server, server.host.PublicKey())
	target.CredentialKind = store.CredentialAgent
	inbound := newFakeSession()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	closer := &trackingCloser{}
	forwarded := &AgentConnection{Agent: keyring, closer: closer}
	err = Connector{Timeout: time.Second}.Connect(ctx, inbound, inbound.windows, target, secrets.Payload{PublicKey: gossh.MarshalAuthorizedKey(authorized)}, forwarded)
	if err != nil {
		t.Fatal(err)
	}
	if server.authCalls.Load() == 0 || !strings.Contains(inbound.output.String(), "downstream-ready") {
		t.Fatalf("agent authentication did not complete: calls=%d output=%q", server.authCalls.Load(), inbound.output.String())
	}
	if !closer.closed.Load() {
		t.Fatal("forwarded agent channel remained open after authentication")
	}
}
