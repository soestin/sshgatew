package downstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anmitsu/go-shlex"
	charmssh "github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// ProxySubsystem connects an inbound SSH subsystem to the same subsystem on
// the selected downstream host. No file data is persisted by SSHGateW.
func ProxySubsystem(ctx context.Context, client *gossh.Client, inbound charmssh.Session, subsystem string) error {
	if subsystem != "sftp" {
		return fmt.Errorf("unsupported subsystem %q", subsystem)
	}
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		return fmt.Errorf("create downstream subsystem channel: %w", err)
	}
	defer channel.Close()
	payload := gossh.Marshal(struct{ Value string }{subsystem})
	ok, err := channel.SendRequest("subsystem", true, payload)
	if err != nil || !ok {
		if err == nil {
			err = errors.New("request rejected")
		}
		return fmt.Errorf("start downstream subsystem: %w", err)
	}
	go gossh.DiscardRequests(requests)
	go func() { _, _ = io.Copy(channel, inbound); _ = channel.CloseWrite() }()
	go func() { _, _ = io.Copy(inbound.Stderr(), channel.Stderr()) }()
	done := make(chan error, 1)
	go func() { _, e := io.Copy(inbound, channel); done <- e }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-done:
		return err
	}
}

// ProxySCP validates and canonicalizes the legacy SCP server command before
// forwarding it. Modern scp uses the SFTP subsystem and does not enter here.
func ProxySCP(ctx context.Context, client *gossh.Client, inbound charmssh.Session) error {
	command, err := SafeSCPCommand(inbound.RawCommand())
	if err != nil {
		return err
	}
	return proxySession(ctx, client, inbound, func(s *gossh.Session) error { return s.Start(command) })
}

func proxySession(ctx context.Context, client *gossh.Client, inbound charmssh.Session, start func(*gossh.Session) error) error {
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("create downstream session: %w", err)
	}
	defer sess.Close()
	sess.Stdin, sess.Stdout, sess.Stderr = inbound, inbound, inbound.Stderr()
	if err = start(sess); err != nil {
		return fmt.Errorf("start downstream protocol: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-ctx.Done():
		_ = sess.Close()
		return ctx.Err()
	case err = <-done:
		var exitErr *gossh.ExitError
		if errors.As(err, &exitErr) {
			_ = inbound.Exit(exitErr.ExitStatus())
		}
		return err
	}
}

func SafeSCPCommand(raw string) (string, error) {
	if strings.ContainsAny(raw, "\x00\r\n") {
		return "", errors.New("invalid SCP command")
	}
	args, err := shlex.Split(raw, true)
	if err != nil || len(args) < 3 || args[0] != "scp" {
		return "", errors.New("only legacy SCP server commands are allowed")
	}
	mode := false
	for _, arg := range args[1 : len(args)-1] {
		if !strings.HasPrefix(arg, "-") || len(arg) < 2 {
			return "", errors.New("invalid SCP option")
		}
		for _, flag := range strings.TrimPrefix(arg, "-") {
			if !strings.ContainsRune("ftrpd", flag) {
				return "", fmt.Errorf("SCP option -%c is not allowed", flag)
			}
			if flag == 'f' || flag == 't' {
				if mode {
					return "", errors.New("SCP command has multiple transfer modes")
				}
				mode = true
			}
		}
	}
	if !mode || args[len(args)-1] == "" {
		return "", errors.New("SCP command requires -f or -t and a path")
	}
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuote(arg)
	}
	return strings.Join(quoted, " "), nil
}

func shellQuote(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t'\"\\$`;&|<>()*?![]{}") {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// CountedCopy is exported for protocol handlers that need transfer auditing.
func CountedCopy(dst io.Writer, src io.Reader) (int64, error) { return io.Copy(dst, src) }
