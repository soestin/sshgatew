package downstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	charmssh "github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
)

type Connector struct{ Timeout time.Duration }

type AgentConnection struct {
	Agent  agent.Agent
	closer io.Closer
	once   sync.Once
}

func (a *AgentConnection) Close() error {
	var err error
	if a != nil {
		a.once.Do(func() { err = a.closer.Close() })
	}
	return err
}

func OpenForwardedAgent(inbound charmssh.Session) (*AgentConnection, error) {
	if !charmssh.AgentRequested(inbound) {
		return nil, errors.New("this target requires agent forwarding; reconnect to SSHGateW with ssh -A")
	}
	ctx := inbound.Context()
	if ctx == nil {
		return nil, errors.New("forwarded agent connection is unavailable")
	}
	sshConn, ok := ctx.Value(charmssh.ContextKeyConn).(gossh.Conn)
	if !ok {
		return nil, errors.New("forwarded agent transport is unavailable")
	}
	channel, requests, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return nil, fmt.Errorf("open forwarded agent: %w", err)
	}
	go gossh.DiscardRequests(requests)
	return &AgentConnection{Agent: agent.NewClient(channel), closer: channel}, nil
}

func ParseHostKey(line string) (gossh.PublicKey, error) {
	k, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}
	return k, nil
}

func ScanHostKey(ctx context.Context, address string, timeout time.Duration) (gossh.PublicKey, error) {
	var observed gossh.PublicKey
	sentinel := errors.New("host key observed")
	cfg := &gossh.ClientConfig{User: "sshgatew-probe", HostKeyCallback: func(_ string, _ net.Addr, k gossh.PublicKey) error { observed = k; return sentinel }, Timeout: timeout}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_, _, _, err = gossh.NewClientConn(conn, address, cfg)
	if observed != nil {
		return observed, nil
	}
	if err == nil {
		return nil, errors.New("server did not present a host key")
	}
	return nil, err
}

func (c Connector) Connect(ctx context.Context, inbound charmssh.Session, windows <-chan charmssh.Window, t store.Target, credential secrets.Payload, forwarded *AgentConnection) error {
	if forwarded != nil {
		defer forwarded.Close()
	}
	pinned, err := ParseHostKey(t.HostPublicKey)
	if err != nil {
		return err
	}
	auth, err := authMethod(t.CredentialKind, credential, forwarded)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
	cfg := &gossh.ClientConfig{User: t.RemoteUsername, Auth: []gossh.AuthMethod{auth}, HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
		if key.Type() != pinned.Type() || !bytes.Equal(key.Marshal(), pinned.Marshal()) {
			return fmt.Errorf("host key mismatch: expected %s, received %s", gossh.FingerprintSHA256(pinned), gossh.FingerprintSHA256(key))
		}
		return nil
	}, Timeout: c.Timeout}
	d := net.Dialer{Timeout: c.Timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial downstream: %w", err)
	}
	defer raw.Close()
	cc, chans, reqs, err := gossh.NewClientConn(raw, addr, cfg)
	if err != nil {
		return fmt.Errorf("downstream handshake: %w", err)
	}
	// The forwarded agent is used only for the authentication handshake. It is
	// deliberately not exposed to the downstream shell.
	if forwarded != nil {
		_ = forwarded.Close()
	}
	client := gossh.NewClient(cc, chans, reqs)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("create downstream session: %w", err)
	}
	defer sess.Close()
	pty, _, ok := inbound.Pty()
	if !ok {
		return errors.New("inbound PTY is required")
	}
	modes := gossh.TerminalModes{gossh.ECHO: 1, gossh.TTY_OP_ISPEED: 14400, gossh.TTY_OP_OSPEED: 14400}
	if err = sess.RequestPty(pty.Term, pty.Window.Height, pty.Window.Width, modes); err != nil {
		return fmt.Errorf("request downstream PTY: %w", err)
	}
	sess.Stdin = inbound
	sess.Stdout = inbound
	sess.Stderr = inbound
	if err = sess.Shell(); err != nil {
		return fmt.Errorf("start downstream shell: %w", err)
	}
	done := make(chan struct{})
	signals := make(chan charmssh.Signal, 16)
	inbound.Signals(signals)
	defer inbound.Signals(nil)
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-done:
		}
	}()
	go func() {
		for {
			select {
			case sig, ok := <-signals:
				if !ok {
					return
				}
				_ = sess.Signal(gossh.Signal(sig))
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case w, open := <-windows:
				if !open {
					return
				}
				_ = sess.WindowChange(w.Height, w.Width)
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	err = sess.Wait()
	closeDone()
	if err != nil {
		var exitErr *gossh.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("downstream exited with status %d", exitErr.ExitStatus())
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func authMethod(kind string, p secrets.Payload, forwarded *AgentConnection) (gossh.AuthMethod, error) {
	switch kind {
	case store.CredentialPassword:
		if p.Password == "" {
			return nil, errors.New("stored password is empty")
		}
		return gossh.Password(p.Password), nil
	case store.CredentialPrivateKey, store.CredentialStoredKey:
		var signer gossh.Signer
		var err error
		if p.Passphrase != "" {
			signer, err = gossh.ParsePrivateKeyWithPassphrase(p.PrivateKey, []byte(p.Passphrase))
		} else {
			signer, err = gossh.ParsePrivateKey(p.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("parse stored private key: %w", err)
		}
		return gossh.PublicKeys(signer), nil
	case store.CredentialAgent:
		if forwarded == nil || forwarded.Agent == nil {
			return nil, errors.New("this target requires a forwarded SSH agent; reconnect with ssh -A")
		}
		expected, _, _, rest, err := gossh.ParseAuthorizedKey(p.PublicKey)
		if err != nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("stored forwarded-agent public key is invalid")
		}
		signers, err := forwarded.Agent.Signers()
		if err != nil {
			return nil, fmt.Errorf("list forwarded-agent identities: %w", err)
		}
		for _, signer := range signers {
			if signer.PublicKey().Type() == expected.Type() && bytes.Equal(signer.PublicKey().Marshal(), expected.Marshal()) {
				return gossh.PublicKeys(signer), nil
			}
		}
		return nil, fmt.Errorf("forwarded agent does not contain required key %s", gossh.FingerprintSHA256(expected))
	default:
		return nil, errors.New("unsupported credential kind")
	}
}
