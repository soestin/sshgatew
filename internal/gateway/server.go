package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	charmssh "github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/config"
	"sshgatew/internal/downstream"
	"sshgatew/internal/oidcdevice"
	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
	"sshgatew/internal/tui"
)

type Server struct {
	cfg              config.Config
	store            *store.Store
	cipher           *secrets.Cipher
	connector        downstream.Connector
	ssh              *charmssh.Server
	log              *slog.Logger
	oidc             oidcAuthenticator
	mu               sync.Mutex
	total            int
	perUser          map[int64]int
	terminals        map[terminalKey]*terminalEntry
	terminalsStopped bool
	terminalWG       sync.WaitGroup
}

type oidcAuthenticator interface {
	Begin(context.Context) (oidcdevice.Login, error)
	Complete(context.Context, oidcdevice.Login) (oidcdevice.Identity, error)
}

func New(cfg config.Config, st *store.Store, cipher *secrets.Cipher, log *slog.Logger) (*Server, error) {
	b, err := os.ReadFile(cfg.HostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read gateway host key: %w", err)
	}
	info, err := os.Lstat(cfg.HostKeyPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("gateway host key must be a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("gateway host key permissions %04o are too open; require 0600", info.Mode().Perm())
	}
	signer, err := gossh.ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse gateway host key: %w", err)
	}
	s := &Server{cfg: cfg, store: st, cipher: cipher, connector: downstream.Connector{Timeout: cfg.DownstreamTimeout.Value()}, log: log, perUser: map[int64]int{}}
	if cfg.OIDC.Enabled {
		s.oidc = oidcdevice.New(oidcdevice.Options{IssuerURL: cfg.OIDC.IssuerURL, ClientID: cfg.OIDC.ClientID, ClientSecret: cfg.OIDC.ClientSecret, UsernameClaim: cfg.OIDC.UsernameClaim, Scopes: cfg.OIDC.Scopes})
	}
	s.ssh = &charmssh.Server{Addr: cfg.ListenAddress, Handler: s.handle, ServerConfigCallback: s.serverConfig, KeyboardInteractiveHandler: s.keyboardInteractive, PtyCallback: func(_ charmssh.Context, p charmssh.Pty) bool { return p.Term != "" }, SessionRequestCallback: s.allowSessionRequest, ChannelHandlers: map[string]charmssh.ChannelHandler{"session": charmssh.DefaultSessionHandler, "direct-tcpip": s.handleDirectTCPIP}, SubsystemHandlers: map[string]charmssh.SubsystemHandler{"sftp": s.handle}, IdleTimeout: cfg.IdleTimeout.Value(), Version: "SSHGateW_0.10"}
	s.ssh.AddHostKey(signer)
	return s, nil
}

func (s *Server) ListenAndServe() error { return s.ssh.ListenAndServe() }
func (s *Server) Shutdown(ctx context.Context) error {
	s.stopTerminals()
	err := s.ssh.Shutdown(ctx)
	done := make(chan struct{})
	go func() { s.terminalWG.Wait(); close(done) }()
	select {
	case <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func nullableUserID(u store.User, err error) *int64 {
	if err != nil {
		return nil
	}
	id := u.ID
	return &id
}

func (s *Server) acquire(u store.User) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= s.cfg.MaxSessions || s.perUser[u.ID] >= s.cfg.MaxSessionsPerUser {
		return false
	}
	s.total++
	s.perUser[u.ID]++
	return true
}
func (s *Server) release(u store.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	s.perUser[u.ID]--
	if s.perUser[u.ID] <= 0 {
		delete(s.perUser, u.ID)
	}
}

func (s *Server) handle(sess charmssh.Session) {
	state, ok := s.stateFromContext(sess.Context())
	if !ok {
		fmt.Fprintln(sess, "Authentication context unavailable.")
		_ = sess.Exit(1)
		return
	}
	u := state.User
	if state.TargetName != "" {
		s.handleRouted(sess, state)
		return
	}
	if _, _, ok := sess.Pty(); !ok {
		fmt.Fprintln(sess, "SSHGateW requires an interactive PTY.")
		_ = sess.Exit(1)
		return
	}
	if !s.acquire(u) {
		fmt.Fprintln(sess, "Session limit reached. Try again later.")
		_ = s.store.Audit(sess.Context(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "gateway.session", Outcome: "denied", Details: `{"reason":"session_limit"}`})
		_ = sess.Exit(1)
		return
	}
	defer s.release(u)
	sess = newInteractiveSession(sess)
	_ = s.store.Audit(sess.Context(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "gateway.session.start", Outcome: "success"})
	defer s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "gateway.session.end", Outcome: "success"})
	status := "Ctrl+] detaches a terminal. Select a detached device to resume it."
	for {
		pty, windows, _ := sess.Pty()
		current, userErr := s.store.UserByID(sess.Context(), u.ID)
		if userErr != nil || !current.Enabled {
			return
		}
		u = current
		m := tui.New(sess.Context(), s.store, s.cipher, s.cfg.DownstreamTimeout.Value(), sess.RemoteAddr().String(), u, status)
		m.ConfigureTerminals(func() map[int64]string { return s.terminalStates(u.ID) })
		if s.oidc != nil {
			m.ConfigureOIDC(s.oidc, s.cfg.OIDC.IssuerURL, s.cfg.OIDC.LoginTimeout.Value(), state.AuthMethod == "publickey")
		}
		result, err := tui.RunRemote(sess.Context(), sess, pty.Window, windows, m)
		if err != nil {
			if sess.Context().Err() == nil {
				s.log.Warn("TUI ended", "user", u.Username, "error", err)
			}
			return
		}
		if result.Quit {
			return
		}
		current, userErr = s.store.UserByID(sess.Context(), u.ID)
		if userErr != nil || !current.Enabled {
			return
		}
		u = current
		if result.CloseTerminal {
			if s.closeTerminal(u.ID, result.TargetID) {
				status = "Session closed."
			} else {
				status = "No running session for this device."
			}
			continue
		}
		if !s.store.CanAccess(sess.Context(), u, result.TargetID) {
			status = "Access was revoked or the target is disabled."
			continue
		}
		target, err := s.store.TargetByID(sess.Context(), result.TargetID)
		if err != nil {
			status = "Target no longer exists."
			continue
		}
		status = s.runTerminal(sess, u, target, windows)
	}
}

func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{}`
	}
	return string(b)
}
func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	return sanitize(err.Error())
}
func sanitize(v string) string {
	if len(v) > 240 {
		v = v[:240]
	}
	return v
}
