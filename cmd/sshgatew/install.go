package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/config"
	"sshgatew/internal/store"
)

type installPaths struct {
	config, dataDir, binary, unit string
}

type installRuntime struct {
	euid       func() int
	executable func() (string, error)
	lookupUser func(string) (*user.User, error)
	run        func(string, ...string) error
	chown      func(string, int, int) error
}

func productionInstallRuntime() installRuntime {
	return installRuntime{
		euid:       os.Geteuid,
		executable: os.Executable,
		lookupUser: user.Lookup,
		chown:      os.Chown,
		run: func(name string, args ...string) error {
			output, err := exec.Command(name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
			}
			return nil
		},
	}
}

func installCommand(configPath string, args []string, in io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(errOut)
	admin := fs.String("admin", "admin", "initial administrator username")
	authorizedKey := fs.String("authorized-key", "", "public key file or inline OpenSSH public key")
	listen := fs.String("listen", "0.0.0.0:2222", "gateway listen address")
	noStart := fs.Bool("no-start", false, "install and enable without starting the service")
	yes := fs.Bool("yes", false, "accept installation without confirmation")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	reader := bufio.NewReader(in)
	interactive := len(args) == 0
	if interactive {
		var err error
		if *admin, err = promptDefault(reader, out, "Administrator username", *admin); err != nil {
			return err
		}
		if *listen, err = promptDefault(reader, out, "Listen address", *listen); err != nil {
			return err
		}
	}
	if *authorizedKey == "" {
		fmt.Fprint(out, "Administrator public key (paste one OpenSSH public key): ")
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		*authorizedKey = strings.TrimSpace(line)
	}
	key, err := loadInstallPublicKey(*authorizedKey)
	if err != nil {
		return err
	}
	if interactive && !*yes {
		fmt.Fprintf(out, "\nInstall SSHGateW %s on %s for administrator %s? [y/N]: ", version, *listen, *admin)
		answer, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if answer = strings.ToLower(strings.TrimSpace(answer)); answer != "y" && answer != "yes" {
			return errors.New("installation cancelled")
		}
	}
	paths := installPaths{config: configPath, dataDir: "/var/lib/sshgatew", binary: "/usr/local/bin/sshgatew", unit: "/etc/systemd/system/sshgatew.service"}
	return performInstall(paths, productionInstallRuntime(), *admin, *listen, key, !*noStart, out)
}

func promptDefault(reader *bufio.Reader, out io.Writer, label, value string) (string, error) {
	fmt.Fprintf(out, "%s [%s]: ", label, value)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if line = strings.TrimSpace(line); line != "" {
		return line, nil
	}
	return value, nil
}

func loadInstallPublicKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("an administrator public key is required")
	}
	b := []byte(value)
	if !strings.ContainsAny(value, " \t") {
		var err error
		if b, err = os.ReadFile(value); err != nil {
			return nil, fmt.Errorf("read administrator public key: %w", err)
		}
	}
	key, comment, _, rest, err := gossh.ParseAuthorizedKey(b)
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		if err == nil {
			err = errors.New("expected exactly one public key")
		}
		return nil, fmt.Errorf("parse administrator public key: %w", err)
	}
	canonical := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key)))
	if comment != "" {
		canonical += " " + comment
	}
	return []byte(canonical + "\n"), nil
}

func performInstall(paths installPaths, runtime installRuntime, admin, listen string, publicKey []byte, start bool, out io.Writer) error {
	if runtime.euid() != 0 {
		return errors.New("installation must run as root; use sudo ./sshgatew install")
	}
	if err := store.ValidateUsername(admin); err != nil {
		return err
	}
	installConfig := config.ForDataDir(paths.dataDir)
	installConfig.ListenAddress = listen
	if err := installConfig.Validate(); err != nil {
		return err
	}
	if _, _, _, rest, err := gossh.ParseAuthorizedKey(publicKey); err != nil || len(bytes.TrimSpace(rest)) != 0 {
		if err == nil {
			err = errors.New("expected exactly one administrator public key")
		}
		return fmt.Errorf("parse administrator public key: %w", err)
	}
	for _, path := range []string{paths.config, filepath.Join(paths.dataDir, "sshgatew.db")} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("SSHGateW is already initialized at %s; refusing to overwrite it", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := ensureServiceUser(runtime); err != nil {
		return err
	}
	serviceUser, err := runtime.lookupUser("sshgatew")
	if err != nil {
		return fmt.Errorf("look up sshgatew service account: %w", err)
	}
	uid, err := strconv.Atoi(serviceUser.Uid)
	if err != nil {
		return err
	}
	if uid == 0 {
		return errors.New("refusing to run SSHGateW with a service account that resolves to UID 0")
	}
	gid, err := strconv.Atoi(serviceUser.Gid)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(paths.dataDir, 0750); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(paths.config), 0750); err != nil {
		return err
	}
	if err = os.Chmod(filepath.Dir(paths.config), 0750); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(paths.binary), 0755); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(paths.unit), 0755); err != nil {
		return err
	}
	if err = runtime.chown(paths.dataDir, uid, gid); err != nil {
		return err
	}
	if err = os.Chmod(paths.dataDir, 0750); err != nil {
		return err
	}
	if err = installCurrentExecutable(paths.binary, runtime); err != nil {
		return err
	}
	keyFile, err := os.CreateTemp("", "sshgatew-admin-key-*.pub")
	if err != nil {
		return err
	}
	keyPath := keyFile.Name()
	defer os.Remove(keyPath)
	if err = keyFile.Chmod(0600); err == nil {
		_, err = keyFile.Write(publicKey)
	}
	if closeErr := keyFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	var initOutput bytes.Buffer
	if err = initCommand(paths.config, []string{"--admin", admin, "--authorized-key", keyPath, "--data-dir", paths.dataDir, "--listen", listen}, strings.NewReader(""), &initOutput, io.Discard); err != nil {
		return fmt.Errorf("initialize SSHGateW: %w", err)
	}
	for _, path := range []string{paths.dataDir, filepath.Join(paths.dataDir, "sshgatew.db"), filepath.Join(paths.dataDir, "master.key"), filepath.Join(paths.dataDir, "ssh_host_ed25519_key")} {
		if err = runtime.chown(path, uid, gid); err != nil {
			return err
		}
	}
	if err = runtime.chown(filepath.Dir(paths.config), 0, gid); err != nil {
		return err
	}
	if err = runtime.chown(paths.config, 0, gid); err != nil {
		return err
	}
	if err = os.Chmod(paths.config, 0640); err != nil {
		return err
	}
	if err = atomicWrite(paths.unit, []byte(systemdUnit(paths.binary, paths.config, paths.dataDir)), 0644); err != nil {
		return err
	}
	if err = runtime.run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if start {
		err = runtime.run("systemctl", "enable", "--now", "sshgatew.service")
	} else {
		err = runtime.run("systemctl", "enable", "sshgatew.service")
	}
	if err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(listen)
	fmt.Fprint(out, initOutput.String())
	fmt.Fprintf(out, "\nInstallation complete.\nService: %s\nConnect: ssh -p %s %s@<gateway-host>\n", map[bool]string{true: "enabled and running", false: "enabled, not started"}[start], port, admin)
	return nil
}

func ensureServiceUser(runtime installRuntime) error {
	if _, err := runtime.lookupUser("sshgatew"); err == nil {
		return nil
	} else if _, unknown := err.(user.UnknownUserError); !unknown {
		return fmt.Errorf("look up sshgatew service account: %w", err)
	}
	return runtime.run("useradd", "--system", "--home-dir", "/var/lib/sshgatew", "--shell", "/usr/sbin/nologin", "sshgatew")
}

func installCurrentExecutable(destination string, runtime installRuntime) error {
	source, err := runtime.executable()
	if err != nil {
		return err
	}
	if sourceInfo, sourceErr := os.Stat(source); sourceErr == nil {
		if destinationInfo, destinationErr := os.Stat(destination); destinationErr == nil && os.SameFile(sourceInfo, destinationInfo) {
			return os.Chmod(destination, 0755)
		}
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temp, err := os.CreateTemp(filepath.Dir(destination), ".sshgatew-install-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err = io.Copy(temp, input); err == nil {
		err = temp.Chmod(0755)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tempPath, destination)
}

func atomicWrite(destination string, content []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(destination), ".sshgatew-install-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err = temp.Write(content); err == nil {
		err = temp.Chmod(mode)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tempPath, destination)
}

func systemdUnit(binary, configPath, dataDir string) string {
	return fmt.Sprintf(`[Unit]
Description=SSHGateW SSH credential gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sshgatew
Group=sshgatew
ExecStart=%s --config %s serve
Restart=on-failure
RestartSec=3s
TimeoutStopSec=15s
LimitNOFILE=8192

NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%s
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
`, binary, configPath, dataDir)
}
