package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	charmssh "github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/config"
	"sshgatew/internal/downstream"
	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
	"sshgatew/internal/tui"
)

type contextKey struct{}

type Server struct {
	cfg       config.Config
	store     *store.Store
	cipher    *secrets.Cipher
	connector downstream.Connector
	ssh       *charmssh.Server
	log       *slog.Logger
	mu        sync.Mutex
	total     int
	perUser   map[int64]int
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
	s.ssh = &charmssh.Server{Addr: cfg.ListenAddress, Handler: s.handle, PublicKeyHandler: s.authenticate, PtyCallback: func(_ charmssh.Context, p charmssh.Pty) bool { return p.Term != "" }, SessionRequestCallback: func(_ charmssh.Session, typ string) bool { return typ == "shell" }, IdleTimeout: cfg.IdleTimeout.Value(), Version: "SSHGateW_0.1"}
	s.ssh.AddHostKey(signer)
	return s, nil
}

func (s *Server) ListenAndServe() error              { return s.ssh.ListenAndServe() }
func (s *Server) Shutdown(ctx context.Context) error { return s.ssh.Shutdown(ctx) }

func (s *Server) authenticate(ctx charmssh.Context, key charmssh.PublicKey) bool {
	fp := gossh.FingerprintSHA256(key)
	u, err := s.store.AuthenticateKey(ctx, ctx.User(), fp)
	outcome := "success"
	if err != nil {
		outcome = "denied"
	}
	uid := nullableUserID(u, err)
	_ = s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: uid, ClaimedUsername: ctx.User(), SourceAddress: ctx.RemoteAddr().String(), EventType: "gateway.auth", Outcome: outcome, Details: jsonString(map[string]any{"key_fingerprint": fp})})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			s.log.Error("gateway authentication lookup failed", "error", err)
		}
		return false
	}
	ctx.SetValue(contextKey{}, u)
	return true
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
	v := sess.Context().Value(contextKey{})
	u, ok := v.(store.User)
	if !ok {
		fmt.Fprintln(sess, "Authentication context unavailable.")
		_ = sess.Exit(1)
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
	if u.TOTPEnabled {
		pty, windows, _ := sess.Pty()
		challenge := tui.NewTOTPChallenge(sess.Context(), s.store, s.cipher, sess.RemoteAddr().String(), u)
		result, err := tui.RunRemote(sess.Context(), sess, pty.Window, windows, challenge)
		outcome := "success"
		if err != nil || !result.Verified {
			outcome = "denied"
		}
		_ = s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "gateway.totp", Outcome: outcome})
		if outcome != "success" {
			_ = sess.Exit(1)
			return
		}
	}
	_ = s.store.Audit(sess.Context(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "gateway.session.start", Outcome: "success"})
	defer s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "gateway.session.end", Outcome: "success"})
	status := ""
	for {
		pty, windows, _ := sess.Pty()
		m := tui.New(sess.Context(), s.store, s.cipher, s.cfg.DownstreamTimeout.Value(), sess.RemoteAddr().String(), u, status)
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
		if !s.store.CanAccess(sess.Context(), u, result.TargetID) {
			status = "Access was revoked or the target is disabled."
			continue
		}
		target, err := s.store.TargetByID(sess.Context(), result.TargetID)
		if err != nil {
			status = "Target no longer exists."
			continue
		}
		start := time.Now()
		_ = s.store.Audit(sess.Context(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "target.connect.start", TargetID: &target.ID, Outcome: "success"})
		var credential secrets.Payload
		if target.CredentialKind == store.CredentialStoredKey {
			if target.IdentityID == nil {
				err = errors.New("stored SSH key reference is missing")
			} else {
				var identity store.SSHIdentity
				identity, err = s.store.SSHIdentityByID(sess.Context(), *target.IdentityID)
				if err == nil {
					credential, err = s.cipher.DecryptSSHIdentity(identity.ID, identity.Nonce, identity.Ciphertext)
				}
			}
		} else {
			credential, err = s.cipher.Decrypt(target.ID, target.CredentialKind, target.Nonce, target.Ciphertext)
		}
		var forwarded *downstream.AgentConnection
		if err == nil && target.CredentialKind == store.CredentialAgent {
			forwarded, err = downstream.OpenForwardedAgent(sess)
		}
		if err == nil {
			err = s.connector.Connect(sess.Context(), sess, windows, target, credential, forwarded)
		}
		outcome := "success"
		if err != nil {
			outcome = "failure"
			status = "Connection ended: " + sanitize(err.Error())
		} else {
			status = "Disconnected from " + target.Name
		}
		_ = s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "target.connect.end", TargetID: &target.ID, Outcome: outcome, Details: jsonString(map[string]any{"duration_ms": time.Since(start).Milliseconds(), "error": sanitizeError(err)})})
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
