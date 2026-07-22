package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"sshgatew/internal/config"
	"sshgatew/internal/downstream"
	"sshgatew/internal/gateway"
	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out, errOut io.Writer) error {
	global := flag.NewFlagSet("sshgatew", flag.ContinueOnError)
	global.SetOutput(errOut)
	configPath := global.String("config", config.DefaultPath, "configuration file")
	showVersion := global.Bool("version", false, "show version")
	if err := global.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintln(out, version)
		return nil
	}
	rest := global.Args()
	if len(rest) == 0 {
		return usage(out)
	}
	if rest[0] == "init" {
		return initCommand(*configPath, rest[1:], in, out, errOut)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	if rest[0] == "serve" {
		return serve(cfg, st)
	}
	return adminCommand(context.Background(), cfg, st, rest, in, out, errOut)
}

func usage(w io.Writer) error {
	fmt.Fprint(w, `SSHGateW - an authenticated SSH gateway

Usage:
  sshgatew [--config path] init --admin USER --authorized-key FILE [--data-dir DIR]
  sshgatew [--config path] serve
  sshgatew [--config path] users|groups|targets|grants|audit ...

Run a command without enough arguments to see its specific usage.
`)
	return nil
}

func initCommand(configPath string, args []string, in io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(errOut)
	admin := fs.String("admin", "", "initial administrator username")
	keyPath := fs.String("authorized-key", "", "administrator public key file")
	dataDir := fs.String("data-dir", "/var/lib/sshgatew", "data directory")
	listen := fs.String("listen", "0.0.0.0:2222", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *admin == "" || *keyPath == "" {
		return errors.New("--admin and --authorized-key are required")
	}
	if err := store.ValidateUsername(*admin); err != nil {
		return err
	}
	pub, canonical, fp, err := readPublicKey(*keyPath)
	if err != nil {
		return err
	}
	_ = pub
	cfg := config.ForDataDir(*dataDir)
	cfg.ListenAddress = *listen
	if err = cfg.Validate(); err != nil {
		return err
	}
	for _, p := range []string{configPath, cfg.DatabasePath, cfg.MasterKeyPath, cfg.HostKeyPath} {
		if _, e := os.Stat(p); e == nil {
			return fmt.Errorf("refusing to overwrite existing %s", p)
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	created := []string{cfg.MasterKeyPath, cfg.HostKeyPath, configPath, cfg.DatabasePath, cfg.DatabasePath + "-wal", cfg.DatabasePath + "-shm"}
	success := false
	defer func() {
		if !success {
			for _, p := range created {
				_ = os.Remove(p)
			}
		}
	}()
	if err = os.MkdirAll(*dataDir, 0750); err != nil {
		return err
	}
	if err = secrets.Generate(cfg.MasterKeyPath); err != nil {
		return fmt.Errorf("create master key: %w", err)
	}
	if err = generateHostKey(cfg.HostKeyPath); err != nil {
		return fmt.Errorf("create host key: %w", err)
	}
	if err = config.Write(configPath, cfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer st.Close()
	u, err := st.AddUser(context.Background(), *admin, store.RoleAdmin)
	if err != nil {
		return err
	}
	if err = st.AddGatewayKey(context.Background(), u.Username, fp, canonical, "bootstrap"); err != nil {
		return err
	}
	_ = st.Audit(context.Background(), store.AuditEvent{ActorUserID: &u.ID, ClaimedUsername: "local-init", SourceAddress: "local", EventType: "system.init", Outcome: "success", Details: `{"version":1}`})
	fmt.Fprintf(out, "Initialized SSHGateW.\nConfig: %s\nDatabase: %s\nGateway host key: %s\nAdministrator key: %s\n", configPath, cfg.DatabasePath, hostFingerprint(cfg.HostKeyPath), fp)
	success = true
	return nil
}

func generateHostKey(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := gossh.MarshalPrivateKey(priv, "SSHGateW host key")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = pem.Encode(f, block); err != nil {
		return err
	}
	return f.Sync()
}
func hostFingerprint(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		return "unknown"
	}
	s, e := gossh.ParsePrivateKey(b)
	if e != nil {
		return "unknown"
	}
	return gossh.FingerprintSHA256(s.PublicKey())
}

func serve(cfg config.Config, st *store.Store) error {
	cipher, err := secrets.Load(cfg.MasterKeyPath)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	var handler slog.Handler
	if cfg.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	}
	logger := slog.New(handler)
	srv, err := gateway.New(cfg, st, cipher, logger)
	if err != nil {
		return err
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	logger.Info("SSHGateW listening", "address", cfg.ListenAddress, "version", version)
	select {
	case err = <-errCh:
		if err != nil {
			return err
		}
		return nil
	case sig := <-signals:
		logger.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

func adminCommand(ctx context.Context, cfg config.Config, st *store.Store, args []string, in io.Reader, out, errOut io.Writer) error {
	switch args[0] {
	case "users":
		return usersCommand(ctx, st, args[1:], out, errOut)
	case "groups":
		return groupsCommand(ctx, st, args[1:], out, errOut)
	case "targets":
		return targetsCommand(ctx, cfg, st, args[1:], in, out, errOut)
	case "grants":
		return grantsCommand(ctx, st, args[1:], out, errOut)
	case "audit":
		return auditCommand(ctx, st, args[1:], out, errOut)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func auditLocal(ctx context.Context, st *store.Store, event string, details map[string]any) error {
	b, _ := json.Marshal(details)
	return st.Audit(ctx, store.AuditEvent{ClaimedUsername: "local-admin", SourceAddress: "local", EventType: event, Outcome: "success", Details: string(b)})
}

func usersCommand(ctx context.Context, st *store.Store, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("users requires list, add, enable, disable, delete, set-role, or keys")
	}
	switch args[0] {
	case "list":
		us, e := st.ListUsers(ctx)
		if e != nil {
			return e
		}
		for _, u := range us {
			state := "enabled"
			if !u.Enabled {
				state = "disabled"
			}
			fmt.Fprintf(out, "%-32s %-8s %s\n", u.Username, u.Role, state)
		}
		return nil
	case "add":
		if len(args) < 2 {
			return errors.New("usage: users add USER [--role role]")
		}
		fs := flag.NewFlagSet("users add", flag.ContinueOnError)
		fs.SetOutput(errOut)
		role := fs.String("role", store.RoleMember, "admin or member")
		if e := fs.Parse(args[2:]); e != nil {
			return e
		}
		if fs.NArg() != 0 {
			return errors.New("usage: users add USER [--role role]")
		}
		u, e := st.AddUser(ctx, args[1], *role)
		if e == nil {
			e = auditLocal(ctx, st, "admin.user.add", map[string]any{"username": u.Username, "role": u.Role})
		}
		return e
	case "enable", "disable":
		if len(args) != 2 {
			return fmt.Errorf("usage: users %s USER", args[0])
		}
		enabled := args[0] == "enable"
		if e := st.SetUserEnabled(ctx, args[1], enabled); e != nil {
			return e
		}
		return auditLocal(ctx, st, "admin.user."+args[0], map[string]any{"username": args[1]})
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: users delete USER")
		}
		if e := st.DeleteUser(ctx, args[1]); e != nil {
			return e
		}
		return auditLocal(ctx, st, "admin.user.delete", map[string]any{"username": args[1]})
	case "set-role":
		if len(args) != 3 {
			return errors.New("usage: users set-role USER admin|member")
		}
		if e := st.SetUserRole(ctx, args[1], args[2]); e != nil {
			return e
		}
		return auditLocal(ctx, st, "admin.user.set_role", map[string]any{"username": args[1], "role": args[2]})
	case "keys":
		return userKeysCommand(ctx, st, args[1:], out, errOut)
	default:
		return fmt.Errorf("unknown users operation %q", args[0])
	}
}
func userKeysCommand(ctx context.Context, st *store.Store, args []string, out, errOut io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: users keys list|add|remove USER")
	}
	op, user := args[0], args[1]
	switch op {
	case "list":
		ks, e := st.ListGatewayKeys(ctx, user)
		if e != nil {
			return e
		}
		for _, k := range ks {
			fmt.Fprintf(out, "%s\t%s\n", k.Fingerprint, k.Label)
		}
		return nil
	case "add":
		fs := flag.NewFlagSet("users keys add", flag.ContinueOnError)
		fs.SetOutput(errOut)
		file := fs.String("file", "", "public key file")
		label := fs.String("label", "", "key label")
		if e := fs.Parse(args[2:]); e != nil {
			return e
		}
		if *file == "" {
			return errors.New("--file is required")
		}
		_, canonical, fp, e := readPublicKey(*file)
		if e != nil {
			return e
		}
		if e = st.AddGatewayKey(ctx, user, fp, canonical, *label); e != nil {
			return e
		}
		return auditLocal(ctx, st, "admin.gateway_key.add", map[string]any{"username": user, "fingerprint": fp})
	case "remove":
		if len(args) != 3 {
			return errors.New("usage: users keys remove USER FINGERPRINT")
		}
		if e := st.RemoveGatewayKey(ctx, user, args[2]); e != nil {
			return e
		}
		return auditLocal(ctx, st, "admin.gateway_key.remove", map[string]any{"username": user, "fingerprint": args[2]})
	default:
		return fmt.Errorf("unknown key operation %q", op)
	}
}
func readPublicKey(path string) (gossh.PublicKey, string, string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, "", "", e
	}
	k, _, _, _, e := gossh.ParseAuthorizedKey(b)
	if e != nil {
		return nil, "", "", fmt.Errorf("parse authorized key: %w", e)
	}
	canonical := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(k)))
	return k, canonical, gossh.FingerprintSHA256(k), nil
}

func groupsCommand(ctx context.Context, st *store.Store, args []string, out, errOut io.Writer) error {
	_ = errOut
	if len(args) == 0 {
		return errors.New("groups requires list, add, delete, or members")
	}
	switch args[0] {
	case "list":
		gs, e := st.ListGroups(ctx)
		if e != nil {
			return e
		}
		members, e := st.ListGroupMembers(ctx)
		if e != nil {
			return e
		}
		for _, g := range gs {
			var names []string
			for _, m := range members {
				if m.Group == g.Name {
					names = append(names, m.Username)
				}
			}
			fmt.Fprintf(out, "%-32s %s\n", g.Name, strings.Join(names, ","))
		}
		return nil
	case "add", "delete":
		if len(args) != 2 {
			return fmt.Errorf("usage: groups %s GROUP", args[0])
		}
		var e error
		if args[0] == "add" {
			e = st.AddGroup(ctx, args[1])
		} else {
			e = st.DeleteGroup(ctx, args[1])
		}
		if e != nil {
			return e
		}
		return auditLocal(ctx, st, "admin.group."+args[0], map[string]any{"group": args[1]})
	case "members":
		if len(args) != 4 || (args[1] != "add" && args[1] != "remove") {
			return errors.New("usage: groups members add|remove GROUP USER")
		}
		if e := st.SetGroupMember(ctx, args[2], args[3], args[1] == "add"); e != nil {
			return e
		}
		return auditLocal(ctx, st, "admin.group.member."+args[1], map[string]any{"group": args[2], "username": args[3]})
	default:
		return fmt.Errorf("unknown groups operation %q", args[0])
	}
}

func targetsCommand(ctx context.Context, cfg config.Config, st *store.Store, args []string, in io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("targets requires list, add, edit, enable, disable, delete, credential, or host-key")
	}
	switch args[0] {
	case "list":
		ts, e := st.ListTargets(ctx)
		if e != nil {
			return e
		}
		for _, t := range ts {
			state := "enabled"
			if !t.Enabled {
				state = "disabled"
			}
			key, _ := downstream.ParseHostKey(t.HostPublicKey)
			fp := "invalid"
			if key != nil {
				fp = gossh.FingerprintSHA256(key)
			}
			fmt.Fprintf(out, "%-24s %s@%s:%d %-11s %-8s %s\n", t.Name, t.RemoteUsername, t.Host, t.Port, t.CredentialKind, state, fp)
		}
		return nil
	case "add":
		return targetAdd(ctx, cfg, st, args[1:], in, out, errOut)
	case "edit":
		return targetEdit(ctx, st, args[1:], errOut)
	case "enable", "disable":
		if len(args) != 2 {
			return fmt.Errorf("usage: targets %s NAME", args[0])
		}
		if e := st.SetTargetEnabled(ctx, args[1], args[0] == "enable"); e != nil {
			return e
		}
		return auditLocal(ctx, st, "admin.target."+args[0], map[string]any{"target": args[1]})
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: targets delete NAME")
		}
		if e := st.DeleteTarget(ctx, args[1]); e != nil {
			return e
		}
		return auditLocal(ctx, st, "admin.target.delete", map[string]any{"target": args[1]})
	case "credential":
		if len(args) < 3 || args[1] != "replace" {
			return errors.New("usage: targets credential replace NAME [--auth kind] [--key-file path]")
		}
		return targetCredential(ctx, cfg, st, args[2], args[3:], in, errOut)
	case "host-key":
		return targetHostKey(ctx, cfg, st, args[1:], out, errOut)
	default:
		return fmt.Errorf("unknown targets operation %q", args[0])
	}
}

func targetAdd(ctx context.Context, cfg config.Config, st *store.Store, args []string, in io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("targets add", flag.ContinueOnError)
	fs.SetOutput(errOut)
	name := fs.String("name", "", "profile name")
	host := fs.String("host", "", "host/IP")
	port := fs.Int("port", 22, "SSH port")
	remote := fs.String("remote-user", "", "remote username")
	kind := fs.String("auth", "", "password, private_key, or forwarded_agent")
	keyFile := fs.String("key-file", "", "private key or forwarded-agent public key file")
	hostKeyFile := fs.String("host-key-file", "", "pinned host public key file")
	accept := fs.Bool("accept-host-key", false, "confirm scanned host key")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *name == "" || *host == "" || *remote == "" || *kind == "" {
		return errors.New("--name, --host, --remote-user, and --auth are required")
	}
	hostKey, err := obtainHostKey(ctx, net.JoinHostPort(*host, strconv.Itoa(*port)), *hostKeyFile, *accept, cfg.DownstreamTimeout.Value(), out)
	if err != nil {
		return err
	}
	canonical := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(hostKey)))
	t, err := st.AddTarget(ctx, store.NewTarget{Name: *name, Host: *host, Port: *port, RemoteUsername: *remote, CredentialKind: *kind, HostKeyAlgorithm: hostKey.Type(), HostPublicKey: canonical})
	if err != nil {
		return err
	}
	payload, err := readCredential(*kind, *keyFile, in)
	if err != nil {
		_ = st.DeleteTarget(ctx, t.Name)
		return err
	}
	cipher, err := secrets.Load(cfg.MasterKeyPath)
	if err != nil {
		_ = st.DeleteTarget(ctx, t.Name)
		return err
	}
	nonce, ciphertext, err := cipher.Encrypt(t.ID, *kind, payload)
	if err != nil {
		_ = st.DeleteTarget(ctx, t.Name)
		return err
	}
	if err = st.SetTargetCredential(ctx, t.ID, nonce, ciphertext); err != nil {
		_ = st.DeleteTarget(ctx, t.Name)
		return err
	}
	return auditLocal(ctx, st, "admin.target.add", map[string]any{"target": t.Name, "host_key": gossh.FingerprintSHA256(hostKey), "credential_kind": *kind})
}
func targetEdit(ctx context.Context, st *store.Store, args []string, errOut io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: targets edit NAME [--host H --port P --remote-user U]")
	}
	t, e := st.TargetByName(ctx, args[0])
	if e != nil {
		return e
	}
	fs := flag.NewFlagSet("targets edit", flag.ContinueOnError)
	fs.SetOutput(errOut)
	host := fs.String("host", t.Host, "host")
	port := fs.Int("port", t.Port, "port")
	remote := fs.String("remote-user", t.RemoteUsername, "remote username")
	if e = fs.Parse(args[1:]); e != nil {
		return e
	}
	if e = st.UpdateTarget(ctx, t.Name, *host, *port, *remote); e != nil {
		return e
	}
	return auditLocal(ctx, st, "admin.target.edit", map[string]any{"target": t.Name})
}
func targetCredential(ctx context.Context, cfg config.Config, st *store.Store, name string, args []string, in io.Reader, errOut io.Writer) error {
	t, e := st.TargetByName(ctx, name)
	if e != nil {
		return e
	}
	fs := flag.NewFlagSet("credential replace", flag.ContinueOnError)
	fs.SetOutput(errOut)
	kind := fs.String("auth", t.CredentialKind, "password, private_key, or forwarded_agent")
	keyFile := fs.String("key-file", "", "private key or forwarded-agent public key file")
	if e = fs.Parse(args); e != nil {
		return e
	}
	payload, e := readCredential(*kind, *keyFile, in)
	if e != nil {
		return e
	}
	cipher, e := secrets.Load(cfg.MasterKeyPath)
	if e != nil {
		return e
	}
	nonce, ct, e := cipher.Encrypt(t.ID, *kind, payload)
	if e != nil {
		return e
	}
	if e = st.SetTargetCredentialKind(ctx, t.ID, *kind, nonce, ct); e != nil {
		return e
	}
	return auditLocal(ctx, st, "admin.target.credential.replace", map[string]any{"target": name, "credential_kind": *kind})
}
func readCredential(kind, keyFile string, in io.Reader) (secrets.Payload, error) {
	switch kind {
	case store.CredentialPassword:
		p, e := readSecret(in, "Downstream password: ")
		return secrets.Payload{Password: p}, e
	case store.CredentialPrivateKey:
		if keyFile == "" {
			return secrets.Payload{}, errors.New("--key-file is required for private_key authentication")
		}
		b, e := os.ReadFile(keyFile)
		if e != nil {
			return secrets.Payload{}, e
		}
		if _, e = gossh.ParsePrivateKey(b); e == nil {
			return secrets.Payload{PrivateKey: b}, nil
		}
		var pass string
		pass, e = readSecret(in, "Private key passphrase (required for encrypted key): ")
		if e != nil {
			return secrets.Payload{}, e
		}
		if _, e = gossh.ParsePrivateKeyWithPassphrase(b, []byte(pass)); e != nil {
			return secrets.Payload{}, fmt.Errorf("parse private key: %w", e)
		}
		return secrets.Payload{PrivateKey: b, Passphrase: pass}, nil
	case store.CredentialAgent:
		if keyFile == "" {
			return secrets.Payload{}, errors.New("--key-file is required and must contain the forwarded-agent public key")
		}
		b, e := os.ReadFile(keyFile)
		if e != nil {
			return secrets.Payload{}, e
		}
		key, _, _, rest, e := gossh.ParseAuthorizedKey(b)
		if e != nil || len(bytes.TrimSpace(rest)) != 0 {
			if e == nil {
				e = errors.New("file must contain exactly one public key")
			}
			return secrets.Payload{}, fmt.Errorf("parse forwarded-agent public key: %w", e)
		}
		return secrets.Payload{PublicKey: []byte(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key))))}, nil
	default:
		return secrets.Payload{}, errors.New("auth must be password, private_key, or forwarded_agent")
	}
}
func readSecret(in io.Reader, prompt string) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		b, e := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), e
	}
	b, e := io.ReadAll(io.LimitReader(in, 1024*1024))
	return strings.TrimRight(string(b), "\r\n"), e
}
func obtainHostKey(ctx context.Context, address, file string, accept bool, timeout time.Duration, out io.Writer) (gossh.PublicKey, error) {
	if file != "" {
		k, _, _, e := readPublicKey(file)
		return k, e
	}
	k, e := downstream.ScanHostKey(ctx, address, timeout)
	if e != nil {
		return nil, e
	}
	fmt.Fprintf(out, "Observed host key: %s %s\n", k.Type(), gossh.FingerprintSHA256(k))
	if !accept {
		return nil, errors.New("host key was not stored; verify the fingerprint out-of-band and repeat with --accept-host-key")
	}
	return k, nil
}
func targetHostKey(ctx context.Context, cfg config.Config, st *store.Store, args []string, out, errOut io.Writer) error {
	if len(args) < 2 || (args[0] != "scan" && args[0] != "replace") {
		return errors.New("usage: targets host-key scan|replace NAME [--host-key-file FILE --accept-host-key]")
	}
	op, name := args[0], args[1]
	t, e := st.TargetByName(ctx, name)
	if e != nil {
		return e
	}
	fs := flag.NewFlagSet("target host-key", flag.ContinueOnError)
	fs.SetOutput(errOut)
	file := fs.String("host-key-file", "", "host public key file")
	accept := fs.Bool("accept-host-key", false, "confirm scanned host key")
	if e = fs.Parse(args[2:]); e != nil {
		return e
	}
	k, e := obtainHostKey(ctx, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), *file, op == "scan" || *accept, cfg.DownstreamTimeout.Value(), out)
	if e != nil {
		return e
	}
	fmt.Fprintf(out, "Pinned:   %s\nObserved: %s\n", fingerprintLine(t.HostPublicKey), gossh.FingerprintSHA256(k))
	if op == "scan" {
		return nil
	}
	if !*accept && *file == "" {
		return errors.New("--accept-host-key is required")
	}
	canonical := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(k)))
	if e = st.SetTargetHostKey(ctx, name, k.Type(), canonical); e != nil {
		return e
	}
	return auditLocal(ctx, st, "admin.target.host_key.replace", map[string]any{"target": name, "fingerprint": gossh.FingerprintSHA256(k)})
}
func fingerprintLine(line string) string {
	k, e := downstream.ParseHostKey(line)
	if e != nil {
		return "invalid"
	}
	return gossh.FingerprintSHA256(k)
}

func grantsCommand(ctx context.Context, st *store.Store, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("grants requires list, add, or remove")
	}
	if args[0] == "list" {
		gs, e := st.ListGrants(ctx)
		if e != nil {
			return e
		}
		for _, g := range gs {
			fmt.Fprintf(out, "%-24s %-8s %s\n", g.Target, g.Kind, g.Principal)
		}
		return nil
	}
	if args[0] != "add" && args[0] != "remove" {
		return errors.New("grants requires list, add, or remove")
	}
	fs := flag.NewFlagSet("grants", flag.ContinueOnError)
	fs.SetOutput(errOut)
	target := fs.String("target", "", "target name")
	user := fs.String("user", "", "username")
	group := fs.String("group", "", "group name")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if *target == "" || ((*user == "") == (*group == "")) {
		return errors.New("--target and exactly one of --user or --group are required")
	}
	kind, principal := "user", *user
	if *group != "" {
		kind, principal = "group", *group
	}
	if e := st.SetGrant(ctx, *target, kind, principal, args[0] == "add"); e != nil {
		return e
	}
	return auditLocal(ctx, st, "admin.grant."+args[0], map[string]any{"target": *target, "kind": kind, "principal": principal})
}
func auditCommand(ctx context.Context, st *store.Store, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "list" {
		fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
		fs.SetOutput(errOut)
		limit := fs.Int("limit", 100, "maximum rows")
		if len(args) > 0 {
			if e := fs.Parse(args[1:]); e != nil {
				return e
			}
		}
		events, e := st.ListAudit(ctx, *limit)
		if e != nil {
			return e
		}
		enc := json.NewEncoder(out)
		for _, event := range events {
			if e = enc.Encode(event); e != nil {
				return e
			}
		}
		return nil
	}
	if args[0] == "prune" {
		fs := flag.NewFlagSet("audit prune", flag.ContinueOnError)
		fs.SetOutput(errOut)
		before := fs.String("before", "", "RFC3339 timestamp")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		t, e := time.Parse(time.RFC3339, *before)
		if e != nil {
			return errors.New("--before must be an RFC3339 timestamp")
		}
		n, e := st.PruneAudit(ctx, t)
		if e != nil {
			return e
		}
		fmt.Fprintf(out, "Pruned %d audit events.\n", n)
		return nil
	}
	return fmt.Errorf("unknown audit operation %q", args[0])
}
