package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	charmssh "github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/downstream"
	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
)

func (s *Server) allowSessionRequest(sess charmssh.Session, typ string) bool {
	switch typ {
	case "shell":
		return true
	case "subsystem":
		return sess.Subsystem() == "sftp"
	case "exec":
		_, err := downstream.SafeSCPCommand(sess.RawCommand())
		return err == nil
	default:
		return false
	}
}

func (s *Server) loadCredential(ctx context.Context, target store.Target) (secrets.Payload, error) {
	if target.CredentialKind == store.CredentialStoredKey {
		if target.IdentityID == nil {
			return secrets.Payload{}, errors.New("stored SSH key reference is missing")
		}
		identity, err := s.store.SSHIdentityByID(ctx, *target.IdentityID)
		if err != nil {
			return secrets.Payload{}, err
		}
		return s.cipher.DecryptSSHIdentity(identity.ID, identity.Nonce, identity.Ciphertext)
	}
	return s.cipher.Decrypt(target.ID, target.CredentialKind, target.Nonce, target.Ciphertext)
}

func (s *Server) handleRouted(sess charmssh.Session, state authState) {
	u := state.User
	if !s.acquire(u) {
		fmt.Fprintln(sess, "Session limit reached.")
		_ = sess.Exit(1)
		return
	}
	defer s.release(u)
	target, err := s.store.TargetByName(sess.Context(), state.TargetName)
	if errors.Is(err, sql.ErrNoRows) {
		err = errors.New("target not found or unavailable")
	}
	capability, protocol := store.CapabilityShell, "shell"
	if sess.Subsystem() == "sftp" {
		capability, protocol = store.CapabilitySFTP, "sftp"
	} else if sess.RawCommand() != "" {
		capability, protocol = store.CapabilitySCP, "scp"
	}
	if err == nil && !s.store.CanAccessCapability(sess.Context(), u, target.ID, capability) {
		err = errors.New("access to this target protocol is denied")
	}
	if err == nil && protocol == "shell" {
		if _, _, ok := sess.Pty(); !ok {
			err = errors.New("routed shell requires a PTY")
		}
	}
	start := time.Now()
	if err == nil {
		_ = s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "target." + protocol + ".start", TargetID: &target.ID, Outcome: "success"})
	}
	var credential secrets.Payload
	if err == nil {
		credential, err = s.loadCredential(sess.Context(), target)
	}
	var forwarded *downstream.AgentConnection
	if err == nil && target.CredentialKind == store.CredentialAgent {
		forwarded, err = downstream.OpenForwardedAgent(sess)
	}
	var client *gossh.Client
	if err == nil {
		client, err = s.connector.Dial(sess.Context(), target, credential, forwarded)
	}
	if client != nil {
		defer client.Close()
	}
	if err == nil {
		switch protocol {
		case "shell":
			pty, windows, _ := sess.Pty()
			_ = pty
			err = downstream.ProxyShell(sess.Context(), client, sess, windows)
		case "sftp":
			err = downstream.ProxySubsystem(sess.Context(), client, sess, "sftp")
		case "scp":
			err = downstream.ProxySCP(sess.Context(), client, sess)
		}
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
		fmt.Fprintln(sess.Stderr(), "SSHGateW:", sanitize(err.Error()))
		_ = sess.Exit(1)
	}
	var targetID *int64
	if target.ID != 0 {
		targetID = &target.ID
	}
	_ = s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: u.Username, SourceAddress: sess.RemoteAddr().String(), EventType: "target." + protocol + ".end", TargetID: targetID, Outcome: outcome, Details: jsonString(map[string]any{"duration_ms": time.Since(start).Milliseconds(), "error": sanitizeError(err)})})
}

type directTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (s *Server) handleDirectTCPIP(_ *charmssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx charmssh.Context) {
	var request directTCPIPData
	if err := gossh.Unmarshal(newChan.ExtraData(), &request); err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "invalid forwarding request")
		return
	}
	state, ok := s.stateFromContext(ctx)
	if !ok || state.TargetName == "" {
		_ = newChan.Reject(gossh.Prohibited, "use USER+TARGET for forwarding")
		return
	}
	target, err := s.store.TargetByName(ctx, state.TargetName)
	if errors.Is(err, sql.ErrNoRows) {
		err = errors.New("target not found or unavailable")
	}
	if err == nil && !s.store.CanAccessCapability(ctx, state.User, target.ID, store.CapabilityForward) {
		err = errors.New("TCP forwarding is not granted")
	}
	if err == nil && !s.store.ForwardAllowed(ctx, target.ID, request.DestAddr, int(request.DestPort)) {
		err = errors.New("TCP destination is not allowed")
	}
	if err == nil && target.CredentialKind == store.CredentialAgent {
		err = errors.New("TCP forwarding requires a stored target credential")
	}
	if err != nil {
		_ = newChan.Reject(gossh.Prohibited, sanitize(err.Error()))
		s.auditForward(state, target, ctx, request, 0, 0, "denied", err, time.Now())
		return
	}
	if !s.acquire(state.User) {
		_ = newChan.Reject(gossh.ResourceShortage, "session limit reached")
		return
	}
	defer s.release(state.User)
	start := time.Now()
	credential, err := s.loadCredential(ctx, target)
	var client *gossh.Client
	if err == nil {
		client, err = s.connector.Dial(ctx, target, credential, nil)
	}
	if client != nil {
		defer client.Close()
	}
	var remote net.Conn
	if err == nil {
		remote, err = client.Dial("tcp", net.JoinHostPort(request.DestAddr, strconv.Itoa(int(request.DestPort))))
	}
	if err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, sanitize(err.Error()))
		s.auditForward(state, target, ctx, request, 0, 0, "failure", err, start)
		return
	}
	defer remote.Close()
	channel, requests, err := newChan.Accept()
	if err != nil {
		return
	}
	go gossh.DiscardRequests(requests)
	var up, down int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		up, _ = io.Copy(remote, channel)
		if c, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	go func() { defer wg.Done(); down, _ = io.Copy(channel, remote); _ = channel.CloseWrite() }()
	wg.Wait()
	_ = channel.Close()
	s.auditForward(state, target, ctx, request, up, down, "success", nil, start)
}

func (s *Server) auditForward(state authState, target store.Target, ctx charmssh.Context, r directTCPIPData, up, down int64, outcome string, err error, start time.Time) {
	var targetID *int64
	if target.ID != 0 {
		targetID = &target.ID
	}
	_ = s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: &state.User.ID, ClaimedUsername: state.User.Username, SourceAddress: ctx.RemoteAddr().String(), EventType: "target.tcp_forward", TargetID: targetID, Outcome: outcome, Details: jsonString(map[string]any{"destination": net.JoinHostPort(r.DestAddr, strconv.Itoa(int(r.DestPort))), "bytes_up": up, "bytes_down": down, "duration_ms": time.Since(start).Milliseconds(), "error": sanitizeError(err)})})
}
