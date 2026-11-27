package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	gossh "golang.org/x/crypto/ssh"
	"sshgatew/internal/store"
)

// loadUserCAs deliberately has no key fallback: certificates must be signed by
// an explicitly trusted authority, even if their fingerprint was enrolled.
func loadUserCAs(path string) (*gossh.CertChecker, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("trusted user CA keys: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("trusted user CA keys must be a regular file without group/other write permission")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var authorities []gossh.PublicKey
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, _, options, rest, err := gossh.ParseAuthorizedKey(line)
		if err != nil || len(options) > 0 || len(bytes.TrimSpace(rest)) > 0 {
			return nil, errors.New("invalid trusted user CA public key")
		}
		if _, ok := key.(*gossh.Certificate); ok {
			return nil, errors.New("trusted user CA must be a public key, not a certificate")
		}
		authorities = append(authorities, key)
	}
	if len(authorities) == 0 {
		return nil, errors.New("trusted user CA file is empty")
	}
	return &gossh.CertChecker{IsUserAuthority: func(key gossh.PublicKey) bool {
		for _, authority := range authorities {
			if bytes.Equal(key.Marshal(), authority.Marshal()) {
				return true
			}
		}
		return false
	}}, nil
}

func (s *Server) authenticateCertificate(meta gossh.ConnMetadata, cert *gossh.Certificate, username, target string) (*gossh.Permissions, error) {
	var u store.User
	var permissions *gossh.Permissions
	err := errors.New("certificate authentication disabled or missing principals")
	if s.certificateChecker != nil && len(cert.ValidPrincipals) > 0 {
		permissions, err = s.certificateChecker.Authenticate(meta, cert)
		if err == nil {
			u, err = s.store.UserForCertificateUsername(context.Background(), username)
			if err == nil {
				username = u.Username
			}
			if err == nil && !u.Enabled {
				err = errors.New("disabled user")
			}
		}
	}
	outcome := "success"
	if err != nil {
		outcome = "denied"
	}
	_ = s.store.Audit(context.Background(), store.AuditEvent{ActorUserID: nullableUserID(u, err), ClaimedUsername: username, SourceAddress: meta.RemoteAddr().String(), EventType: "gateway.auth.certificate", Outcome: outcome, Details: jsonString(map[string]any{"certificate_username": meta.User(), "target": target, "serial": cert.Serial, "key_id": cert.KeyId, "ca_fingerprint": gossh.FingerprintSHA256(cert.SignatureKey)})})
	if err != nil {
		return nil, errors.New("permission denied")
	}
	result := authPermissions(username, target, "certificate")
	// x/crypto/ssh enforces source-address after this callback. Retain it rather
	// than discarding the certificate's critical restrictions during mapping.
	result.CriticalOptions = permissions.CriticalOptions
	if !u.TOTPEnabled {
		return result, nil
	}
	return nil, &gossh.PartialSuccessError{Next: gossh.ServerAuthCallbacks{KeyboardInteractiveCallback: func(_ gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
		if err := s.authenticateTOTP(u, username, meta.RemoteAddr().String(), challenge); err != nil {
			return nil, err
		}
		return result, nil
	}}}
}
