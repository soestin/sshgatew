package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/config"
	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
)

func startProtocolTarget(t *testing.T) (string, gossh.PublicKey) {
	t.Helper()
	host := signer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gossh.ServerConfig{PasswordCallback: func(_ gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		if string(password) != "downstream-secret" {
			return nil, fmt.Errorf("denied")
		}
		return nil, nil
	}}
	cfg.AddHostKey(host)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				conn, chans, reqs, e := gossh.NewServerConn(raw, cfg)
				if e != nil {
					_ = raw.Close()
					return
				}
				defer conn.Close()
				go gossh.DiscardRequests(reqs)
				for incoming := range chans {
					switch incoming.ChannelType() {
					case "session":
						ch, requests, e := incoming.Accept()
						if e != nil {
							continue
						}
						go func() {
							defer ch.Close()
							for req := range requests {
								switch req.Type {
								case "pty-req":
									_ = req.Reply(true, nil)
								case "shell":
									_ = req.Reply(true, nil)
									_, _ = io.WriteString(ch, "routed-shell-ok\n")
									_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
									return
								case "subsystem":
									var p struct{ Value string }
									_ = gossh.Unmarshal(req.Payload, &p)
									if p.Value != "sftp" {
										_ = req.Reply(false, nil)
										continue
									}
									_ = req.Reply(true, nil)
									_, _ = io.WriteString(ch, "sftp-proxy-ok")
									_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
									return
								default:
									_ = req.Reply(false, nil)
								}
							}
						}()
					case "direct-tcpip":
						ch, requests, e := incoming.Accept()
						if e != nil {
							continue
						}
						go gossh.DiscardRequests(requests)
						go func() { defer ch.Close(); _, _ = io.Copy(ch, ch) }()
					default:
						_ = incoming.Reject(gossh.UnknownChannelType, "unsupported")
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), host.PublicKey()
}

func TestRoutedShellSFTPAndTCPForwarding(t *testing.T) {
	targetAddr, targetHostKey := startProtocolTarget(t)
	targetHost, targetPortText, _ := net.SplitHostPort(targetAddr)
	targetPort, _ := net.LookupPort("tcp", targetPortText)
	dir := t.TempDir()
	cfg := config.ForDataDir(dir)
	cfg.ListenAddress = freeAddress(t)
	cfg.IdleTimeout = config.Duration(time.Minute)
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
	clientSigner := signer(t)
	user, err := st.AddUser(context.Background(), "alice", store.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.AddGatewayKey(context.Background(), user.Username, gossh.FingerprintSHA256(clientSigner.PublicKey()), strings.TrimSpace(string(gossh.MarshalAuthorizedKey(clientSigner.PublicKey()))), "test"); err != nil {
		t.Fatal(err)
	}
	target, err := st.AddTarget(context.Background(), store.NewTarget{Name: "prod", Host: targetHost, Port: targetPort, RemoteUsername: "root", CredentialKind: store.CredentialPassword, HostKeyAlgorithm: targetHostKey.Type(), HostPublicKey: strings.TrimSpace(string(gossh.MarshalAuthorizedKey(targetHostKey)))})
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := cipher.Encrypt(target.ID, store.CredentialPassword, secrets.Payload{Password: "downstream-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err = st.SetTargetCredential(context.Background(), target.ID, nonce, ciphertext); err != nil {
		t.Fatal(err)
	}
	if err = st.SetGrantCapabilities(context.Background(), target.Name, "user", user.Username, true, true, true, true, true); err != nil {
		t.Fatal(err)
	}
	if err = st.AddForwardRule(context.Background(), target.Name, "db.internal", 5432); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, cipher, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	clientCfg := &gossh.ClientConfig{User: "alice+prod", Auth: []gossh.AuthMethod{gossh.PublicKeys(clientSigner)}, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second}
	var client *gossh.Client
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		client, err = gossh.Dial("tcp", cfg.ListenAddress, clientCfg)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	shell, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var shellOut bytes.Buffer
	shell.Stdout = &shellOut
	if err = shell.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err = shell.Shell(); err != nil {
		t.Fatal(err)
	}
	if err = shell.Wait(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shellOut.String(), "routed-shell-ok") {
		t.Fatalf("shell output=%q", shellOut.String())
	}
	sftp, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	sftpOut, err := sftp.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = sftp.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	sftpBytes, err := io.ReadAll(sftpOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(sftpBytes) != "sftp-proxy-ok" {
		t.Fatalf("sftp output=%q", sftpBytes)
	}
	forward, err := client.Dial("tcp", "db.internal:5432")
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()
	if _, err = forward.Write([]byte("forward-ok")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("forward-ok"))
	if _, err = io.ReadFull(forward, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "forward-ok" {
		t.Fatalf("forward reply=%q", reply)
	}
}
