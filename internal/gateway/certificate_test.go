package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"sshgatew/internal/config"
	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
	"sshgatew/internal/totp"
)

func TestCertificateAuthenticationHandshake(t *testing.T) {
	dir := t.TempDir()
	cfg := config.ForDataDir(dir)
	cfg.ListenAddress = freeAddress(t)
	cfg.CertificateUsernameAliases = map[string]string{"web-alice": "alice", "web-disabled": "disabled"}
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
	if _, err := st.AddUser(context.Background(), "alice", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUser(context.Background(), "disabled", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserEnabled(context.Background(), "disabled", false); err != nil {
		t.Fatal(err)
	}
	ca := signer(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecCA, err := gossh.NewSignerFromKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	key := signer(t)
	cfg.TrustedUserCAKeys = filepath.Join(dir, "ca.pub")
	if err := os.WriteFile(cfg.TrustedUserCAKeys, append(gossh.MarshalAuthorizedKey(ca.PublicKey()), gossh.MarshalAuthorizedKey(ecCA.PublicKey())...), 0644); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, cipher, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	for deadline := time.Now().Add(3 * time.Second); ; {
		c, err := net.DialTimeout("tcp", cfg.ListenAddress, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cases := []struct {
		name, user string
		change     func(*gossh.Certificate)
		authority  gossh.Signer
		allow      bool
	}{
		{name: "trusted", user: "alice", allow: true},
		{name: "browser alias", user: "web-alice", change: func(c *gossh.Certificate) { c.ValidPrincipals = []string{"web-alice"} }, allow: true},
		{name: "alias wrong principal", user: "web-alice"},
		{name: "alias untrusted CA", user: "web-alice", authority: signer(t), change: func(c *gossh.Certificate) { c.ValidPrincipals = []string{"web-alice"} }},
		{name: "alias disabled user", user: "web-disabled", change: func(c *gossh.Certificate) { c.ValidPrincipals = []string{"web-disabled"} }},
		{name: "trusted ECDSA CA", user: "alice", authority: ecCA, allow: true},
		{name: "routed exact principal", user: "alice+prod-1", change: func(c *gossh.Certificate) { c.ValidPrincipals = []string{"alice+prod-1"} }, allow: true},
		{name: "route requires explicit principal", user: "alice+prod-1"},
		{name: "disabled user", user: "disabled", change: func(c *gossh.Certificate) { c.ValidPrincipals = []string{"disabled"} }},
		{name: "unknown user", user: "bob", change: func(c *gossh.Certificate) { c.ValidPrincipals = []string{"bob"} }},
		{name: "wrong principal", user: "alice", change: func(c *gossh.Certificate) { c.ValidPrincipals = []string{"bob"} }},
		{name: "empty principals", user: "alice", change: func(c *gossh.Certificate) { c.ValidPrincipals = nil }},
		{name: "untrusted CA", user: "alice", authority: signer(t)},
		{name: "expired", user: "alice", change: func(c *gossh.Certificate) { c.ValidBefore = uint64(time.Now().Add(-time.Minute).Unix()) }},
		{name: "not yet valid", user: "alice", change: func(c *gossh.Certificate) { c.ValidAfter = uint64(time.Now().Add(time.Minute).Unix()) }},
		{name: "host certificate", user: "alice", change: func(c *gossh.Certificate) { c.CertType = gossh.HostCert }},
		{name: "force command rejected", user: "alice", change: func(c *gossh.Certificate) { c.CriticalOptions = map[string]string{"force-command": "sh"} }},
		{name: "source address allowed", user: "alice", change: func(c *gossh.Certificate) { c.CriticalOptions = map[string]string{"source-address": "127.0.0.1/32"} }, allow: true},
		{name: "source address denied", user: "alice", change: func(c *gossh.Certificate) { c.CriticalOptions = map[string]string{"source-address": "192.0.2.1/32"} }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cert := &gossh.Certificate{Key: key.PublicKey(), CertType: gossh.UserCert, ValidPrincipals: []string{"alice"}, ValidAfter: uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
			if tt.change != nil {
				tt.change(cert)
			}
			authority := tt.authority
			if authority == nil {
				authority = ca
			}
			if len(cert.ValidPrincipals) == 0 {
				// Current x/crypto refuses to issue an unrestricted certificate.
				// Construct the legacy wire format to verify server rejection.
				cert.Nonce = make([]byte, 32)
				if _, err := rand.Read(cert.Nonce); err != nil {
					t.Fatal(err)
				}
				cert.SignatureKey = authority.PublicKey()
				unsigned := cert.Marshal()
				cert.Signature, err = authority.Sign(rand.Reader, unsigned[:len(unsigned)-4])
				if err != nil {
					t.Fatal(err)
				}
			} else if err := cert.SignCert(rand.Reader, authority); err != nil {
				t.Fatal(err)
			}
			certSigner, err := gossh.NewCertSigner(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			client, err := gossh.Dial("tcp", cfg.ListenAddress, &gossh.ClientConfig{User: tt.user, Auth: []gossh.AuthMethod{gossh.PublicKeys(certSigner)}, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second})
			if client != nil {
				if tt.name == "browser alias" {
					session, err := client.NewSession()
					if err != nil {
						t.Fatal(err)
					}
					var output bytes.Buffer
					session.Stdout = &output
					deadline := time.AfterFunc(3*time.Second, func() { client.Close() })
					if err := session.Shell(); err != nil {
						t.Fatal(err)
					}
					_ = session.Wait()
					deadline.Stop()
					if !strings.Contains(output.String(), "requires an interactive PTY") {
						t.Fatalf("alias session did not resolve canonical user: %q", output.String())
					}
				}
				client.Close()
			}
			if (err == nil) != tt.allow {
				t.Fatalf("allowed=%v, error=%v", tt.allow, err)
			}
		})
	}
	// Certificate login must not bypass a user's existing second factor.
	u, err := st.UserByName(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := cipher.EncryptTOTP(u.ID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserTOTP(context.Background(), u.ID, nonce, ciphertext); err != nil {
		t.Fatal(err)
	}
	cert := &gossh.Certificate{Key: key.PublicKey(), CertType: gossh.UserCert, ValidPrincipals: []string{"alice"}, ValidAfter: uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	cs, err := gossh.NewCertSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := &gossh.ClientConfig{User: "alice", Auth: []gossh.AuthMethod{gossh.PublicKeys(cs)}, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second}
	if client, err := gossh.Dial("tcp", cfg.ListenAddress, clientConfig); err == nil {
		client.Close()
		t.Fatal("certificate bypassed TOTP")
	}
	code, _, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.Auth = append(clientConfig.Auth, gossh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) { return []string{code}, nil }))
	client, err := gossh.Dial("tcp", cfg.ListenAddress, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()

}

func TestLoadUserCAs(t *testing.T) {
	if checker, err := loadUserCAs(""); err != nil || checker != nil {
		t.Fatal("empty setting should disable certificate authentication")
	}
	path := filepath.Join(t.TempDir(), "ca.pub")
	if _, err := loadUserCAs(path); err == nil {
		t.Fatal("missing file accepted")
	}
	for _, data := range []string{"", "# comment\n", "invalid", "restrict " + string(gossh.MarshalAuthorizedKey(signer(t).PublicKey()))} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadUserCAs(path); err == nil {
			t.Fatalf("accepted invalid CA file %q", data)
		}
	}
	if err := os.WriteFile(path, gossh.MarshalAuthorizedKey(signer(t).PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUserCAs(path); err == nil {
		t.Fatal("writable CA file accepted")
	}
}
