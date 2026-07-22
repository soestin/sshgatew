package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"sshgatew/internal/config"
	"sshgatew/internal/store"
)

func TestSingleBinaryInstaller(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "downloaded-sshgatew")
	if err := os.WriteFile(source, []byte("test binary"), 0700); err != nil {
		t.Fatal(err)
	}
	paths := installPaths{
		config:  filepath.Join(root, "etc", "sshgatew", "config.toml"),
		dataDir: filepath.Join(root, "var", "lib", "sshgatew"),
		binary:  filepath.Join(root, "usr", "local", "bin", "sshgatew"),
		unit:    filepath.Join(root, "etc", "systemd", "system", "sshgatew.service"),
	}
	createdUser := false
	var commands []string
	runtime := installRuntime{
		euid:       func() int { return 0 },
		executable: func() (string, error) { return source, nil },
		lookupUser: func(name string) (*user.User, error) {
			if name != "sshgatew" || !createdUser {
				return nil, user.UnknownUserError(name)
			}
			return &user.User{Username: name, Uid: strconv.Itoa(12345), Gid: strconv.Itoa(12345)}, nil
		},
		run: func(name string, args ...string) error {
			commands = append(commands, name+" "+strings.Join(args, " "))
			if name == "useradd" {
				createdUser = true
			}
			return nil
		},
		chown: func(string, int, int) error { return nil },
	}
	keyPath := filepath.Join(root, "admin.pub")
	writePublicKey(t, keyPath)
	publicKey, err := loadInstallPublicKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err = performInstall(paths, runtime, "admin", "127.0.0.1:2222", publicKey, true, &output); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"useradd --system", "systemctl daemon-reload", "systemctl enable --now sshgatew.service"} {
		if !strings.Contains(strings.Join(commands, "\n"), expected) {
			t.Fatalf("missing command %q in %#v", expected, commands)
		}
	}
	for path, mode := range map[string]os.FileMode{paths.binary: 0755, paths.config: 0640, paths.unit: 0644, filepath.Join(paths.dataDir, "master.key"): 0600} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat %s: %v", path, statErr)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s mode=%v, want %v", path, info.Mode().Perm(), mode)
		}
	}
	cfg, err := config.Load(paths.config)
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	users, err := database.ListUsers(t.Context())
	if err != nil || len(users) != 1 || users[0].Username != "admin" || users[0].Role != store.RoleAdmin {
		t.Fatalf("users=%#v err=%v", users, err)
	}
	if !strings.Contains(output.String(), "Installation complete") || !strings.Contains(output.String(), "ssh -p 2222 admin@<gateway-host>") {
		t.Fatalf("unexpected installer output: %s", output.String())
	}
	if err = performInstall(paths, runtime, "admin", "127.0.0.1:2222", publicKey, true, &output); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("repeat installation was not rejected: %v", err)
	}
}

func TestInstallerRequiresRoot(t *testing.T) {
	err := performInstall(installPaths{}, installRuntime{euid: func() int { return 1000 }}, "admin", "127.0.0.1:2222", nil, true, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstallPublicKeyAcceptsInlineSecurityKey(t *testing.T) {
	const key = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAOdpU8BsAjXH/yTiCCi9GUqE6J6utSVpOUrxQ16kxjFAAAABHNzaDo= yubikey1"
	parsed, err := loadInstallPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(parsed), "yubikey1") {
		t.Fatalf("comment was not retained: %q", parsed)
	}
	if _, err = loadInstallPublicKey("not-a-key"); err == nil {
		t.Fatal("invalid key was accepted")
	}
}

func TestSystemdUnitUsesInstalledPaths(t *testing.T) {
	unit := systemdUnit("/usr/local/bin/sshgatew", config.DefaultPath, "/var/lib/sshgatew")
	for _, expected := range []string{
		"ExecStart=/usr/local/bin/sshgatew --config /etc/sshgatew/config.toml serve",
		"ReadWritePaths=/var/lib/sshgatew",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(unit, expected) {
			t.Fatal(fmt.Errorf("generated unit missing %q", expected))
		}
	}
	deployed, err := os.ReadFile(filepath.Join("..", "..", "deploy", "sshgatew.service"))
	if err != nil {
		t.Fatal(err)
	}
	if unit != string(deployed) {
		t.Fatal("embedded installer unit differs from deploy/sshgatew.service")
	}
}

func TestEnsureServiceUserPropagatesLookupFailure(t *testing.T) {
	want := errors.New("lookup failed")
	err := ensureServiceUser(installRuntime{lookupUser: func(string) (*user.User, error) { return nil, want }})
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}
