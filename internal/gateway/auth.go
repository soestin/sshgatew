package gateway

import (
	"context"
	"errors"
	"strings"
	"time"

	charmssh "github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/store"
	"sshgatew/internal/totp"
)

type authState struct {
	User       store.User
	TargetName string
}

func authPermissions(username, target string) *gossh.Permissions {
	return &gossh.Permissions{Extensions: map[string]string{"sshgatew-user": username, "sshgatew-target": target}}
}

func (s *Server) stateFromContext(ctx charmssh.Context) (authState, bool) {
	username, target, err := splitRoutedUsername(ctx.User())
	if err != nil {
		return authState{}, false
	}
	u, err := s.store.UserByName(context.Background(), username)
	if err != nil || !u.Enabled {
		return authState{}, false
	}
	return authState{User: u, TargetName: target}, true
}

func splitRoutedUsername(value string) (string, string, error) {
	parts := strings.Split(value, "+")
	if len(parts) == 1 {
		return strings.ToLower(parts[0]), "", nil
	}
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("username must be USER or USER+TARGET")
	}
	if store.ValidateUsername(parts[0]) != nil {
		return "", "", errors.New("invalid gateway username")
	}
	return strings.ToLower(parts[0]), strings.ToLower(parts[1]), nil
}

func (s *Server) serverConfig(ctx charmssh.Context) *gossh.ServerConfig {
	return &gossh.ServerConfig{PublicKeyCallback: func(meta gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		username, target, err := splitRoutedUsername(meta.User())
		if err != nil {
			return nil, err
		}
		fp := gossh.FingerprintSHA256(key)
		u, err := s.store.AuthenticateKey(context.Background(), username, fp)
		outcome := "success"
		if err != nil {
			outcome = "denied"
		}
		uid := nullableUserID(u, err)
		_ = s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: uid, ClaimedUsername: username, SourceAddress: meta.RemoteAddr().String(), EventType: "gateway.auth.key", Outcome: outcome, Details: jsonString(map[string]any{"key_fingerprint": fp, "target": target})})
		if err != nil {
			return nil, errors.New("permission denied")
		}
		if !u.TOTPEnabled {
			return authPermissions(username, target), nil
		}
		return nil, &gossh.PartialSuccessError{Next: gossh.ServerAuthCallbacks{KeyboardInteractiveCallback: func(_ gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
			answers, promptErr := challenge("SSHGateW two-factor authentication", "", []string{"TOTP code: "}, []bool{false})
			if promptErr != nil || len(answers) != 1 {
				s.auditTOTP(u, username, meta.RemoteAddr().String(), "denied")
				return nil, errors.New("TOTP required")
			}
			config, verifyErr := s.store.UserTOTP(context.Background(), u.ID)
			if verifyErr == nil {
				var secret string
				secret, verifyErr = s.cipher.DecryptTOTP(u.ID, config.Nonce, config.Ciphertext)
				if verifyErr == nil {
					var counter int64
					var valid bool
					counter, valid = totp.Validate(secret, answers[0], time.Now())
					if !valid {
						verifyErr = errors.New("invalid TOTP code")
					} else {
						verifyErr = s.store.ConsumeTOTPCounter(context.Background(), u.ID, counter)
					}
				}
			}
			if verifyErr != nil {
				s.auditTOTP(u, username, meta.RemoteAddr().String(), "denied")
				return nil, errors.New("invalid TOTP code")
			}
			s.auditTOTP(u, username, meta.RemoteAddr().String(), "success")
			return authPermissions(username, target), nil
		}}}
	}}
}

func (s *Server) auditTOTP(u store.User, username, source, outcome string) {
	_ = s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: username, SourceAddress: source, EventType: "gateway.auth.totp", Outcome: outcome})
}
