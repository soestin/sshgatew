package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	charmssh "github.com/charmbracelet/ssh"

	"sshgatew/internal/downstream"
	"sshgatew/internal/store"
)

type terminalKey struct{ userID, targetID int64 }
type terminalEntry struct {
	terminal *downstream.Terminal
	cancel   context.CancelFunc
	target   store.Target
	closed   bool
}

func (s *Server) terminalStates(userID int64) map[int64]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	states := map[int64]string{}
	for key, entry := range s.terminals {
		if key.userID != userID {
			continue
		}
		state := "STARTING"
		if entry.terminal != nil {
			select {
			case <-entry.terminal.Done():
				continue
			default:
			}
			state = "DETACHED"
			if entry.terminal.Busy() {
				state = "ATTACHED"
			}
		}
		states[key.targetID] = state
	}
	return states
}

func (s *Server) openTerminal(sess charmssh.Session, user store.User, target store.Target) (*downstream.Terminal, error) {
	current, err := s.store.UserByID(sess.Context(), user.ID)
	if err != nil || !current.Enabled || !s.store.CanAccess(sess.Context(), current, target.ID) {
		return nil, errors.New("access to this device is denied")
	}
	key := terminalKey{user.ID, target.ID}
	s.mu.Lock()
	if s.terminalsStopped {
		s.mu.Unlock()
		return nil, errors.New("gateway is shutting down")
	}
	if entry := s.terminals[key]; entry != nil {
		if entry.terminal == nil {
			s.mu.Unlock()
			return nil, errors.New("terminal is still starting in another connection")
		}
		if !sameTerminalTarget(entry.target, target) {
			entry.terminal.Close()
			s.mu.Unlock()
			return nil, errors.New("device connection settings changed; its previous terminal was closed")
		}
		select {
		case <-entry.terminal.Done():
			delete(s.terminals, key)
		default:
			s.mu.Unlock()
			return entry.terminal, nil
		}
	}
	count := 0
	for k := range s.terminals {
		if k.userID == user.ID {
			count++
		}
	}
	if len(s.terminals) >= s.cfg.MaxSessions || count >= s.cfg.MaxSessionsPerUser {
		s.mu.Unlock()
		return nil, errors.New("terminal limit reached; close an existing session first")
	}
	ctx, cancel := context.WithTimeout(sess.Context(), s.cfg.DownstreamTimeout.Value())
	entry := &terminalEntry{cancel: cancel, target: target}
	if s.terminals == nil {
		s.terminals = map[terminalKey]*terminalEntry{}
	}
	s.terminals[key] = entry
	s.mu.Unlock()
	remove := func() {
		s.mu.Lock()
		if s.terminals[key] == entry {
			delete(s.terminals, key)
		}
		s.mu.Unlock()
	}
	credential, err := s.loadCredential(ctx, target)
	var forwarded *downstream.AgentConnection
	if err == nil && target.CredentialKind == store.CredentialAgent {
		forwarded, err = downstream.OpenForwardedAgent(sess)
	}
	var terminal *downstream.Terminal
	if err == nil {
		client, dialErr := s.connector.Dial(ctx, target, credential, forwarded)
		err = dialErr
		if err == nil {
			pty, _, _ := sess.Pty()
			// PTY setup is also bounded by the dial timeout and canceled login.
			stop := context.AfterFunc(ctx, func() { _ = client.Close() })
			terminal, err = downstream.StartTerminal(client, pty)
			stop()
			if err != nil {
				_ = client.Close()
			}
		}
	}
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
		if terminal != nil {
			terminal.Close()
		}
	}
	cancel()
	if err != nil {
		remove()
		s.auditTerminal(user, target, sess.RemoteAddr().String(), "start", "failure", err)
		return nil, err
	}
	s.mu.Lock()
	if s.terminalsStopped || s.terminals[key] != entry || entry.closed {
		s.mu.Unlock()
		terminal.Close()
		remove()
		return nil, errors.New("terminal was closed while starting")
	}
	entry.terminal = terminal
	s.terminalWG.Add(1)
	s.mu.Unlock()
	s.auditTerminal(user, target, sess.RemoteAddr().String(), "start", "success", nil)
	go func() {
		defer s.terminalWG.Done()
		defer remove()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-terminal.Done():
				s.auditTerminal(user, target, "", "end", "success", terminal.Err())
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				current, err := s.store.UserByID(ctx, user.ID)
				allowed := err == nil && current.Enabled && s.store.CanAccess(ctx, current, target.ID)
				latest, targetErr := s.store.TargetByID(ctx, target.ID)
				allowed = allowed && targetErr == nil && sameTerminalTarget(target, latest)
				cancel()
				if !allowed {
					terminal.Close()
				}
			}
		}
	}()
	return terminal, nil
}

func sameTerminalTarget(a, b store.Target) bool {
	return a.Host == b.Host && a.Port == b.Port && a.RemoteUsername == b.RemoteUsername && a.HostPublicKey == b.HostPublicKey
}

func (s *Server) closeTerminal(userID, targetID int64) bool {
	s.mu.Lock()
	entry := s.terminals[terminalKey{userID, targetID}]
	var terminal *downstream.Terminal
	if entry != nil {
		entry.closed = true
		terminal = entry.terminal
	}
	s.mu.Unlock()
	if entry == nil {
		return false
	}
	entry.cancel()
	if terminal != nil {
		terminal.Close()
		select {
		case <-terminal.Done():
		case <-time.After(5 * time.Second):
		}
	}
	return true
}

func (s *Server) stopTerminals() {
	s.mu.Lock()
	s.terminalsStopped = true
	entries := make([]terminalEntry, 0, len(s.terminals))
	for _, entry := range s.terminals {
		entries = append(entries, *entry)
	}
	s.mu.Unlock()
	for _, entry := range entries {
		entry.cancel()
		if entry.terminal != nil {
			entry.terminal.Close()
		}
	}
}

func (s *Server) auditTerminal(user store.User, target store.Target, source, event, outcome string, err error) {
	if err != nil {
		outcome = "failure"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.store.Audit(ctx, store.AuditEvent{ActorUserID: &user.ID, ClaimedUsername: user.Username, TargetID: &target.ID, SourceAddress: source, EventType: "terminal." + event, Outcome: outcome, Details: jsonString(map[string]any{"error": sanitizeError(err)})})
}

func (s *Server) runTerminal(sess charmssh.Session, user store.User, target store.Target, windows <-chan charmssh.Window) string {
	terminal, err := s.openTerminal(sess, user, target)
	if err != nil {
		return "Cannot open terminal: " + sanitize(err.Error())
	}
	detached, err := terminal.Attach(sess.Context(), sess, sess.(*interactiveSession), windows)
	if errors.Is(err, downstream.ErrTerminalBusy) {
		return "Terminal is attached in another connection. Detach it there first, or close the session here."
	}
	if detached {
		s.auditTerminal(user, target, sess.RemoteAddr().String(), "detach", "success", nil)
		return "Detached from " + target.Name + ". Select it to resume; x closes the session."
	}
	if err != nil {
		return "Terminal ended: " + sanitize(err.Error())
	}
	return fmt.Sprintf("Disconnected from %s (shell exited)", target.Name)
}
