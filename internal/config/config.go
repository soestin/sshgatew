package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const DefaultPath = "/etc/sshgatew/config.toml"

type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }
func (d Duration) Value() time.Duration         { return time.Duration(d) }

type OIDCConfig struct {
	Enabled       bool     `toml:"enabled"`
	IssuerURL     string   `toml:"issuer_url"`
	ClientID      string   `toml:"client_id"`
	ClientSecret  string   `toml:"client_secret"`
	UsernameClaim string   `toml:"username_claim"`
	Scopes        []string `toml:"scopes"`
	LoginTimeout  Duration `toml:"login_timeout"`
}

type Config struct {
	ListenAddress      string     `toml:"listen_address"`
	DatabasePath       string     `toml:"database_path"`
	MasterKeyPath      string     `toml:"master_key_path"`
	HostKeyPath        string     `toml:"host_key_path"`
	IdleTimeout        Duration   `toml:"idle_timeout"`
	DownstreamTimeout  Duration   `toml:"downstream_dial_timeout"`
	MaxSessions        int        `toml:"max_sessions"`
	MaxSessionsPerUser int        `toml:"max_sessions_per_user"`
	LogLevel           string     `toml:"log_level"`
	LogFormat          string     `toml:"log_format"`
	OIDC               OIDCConfig `toml:"oidc"`
}

func Default() Config {
	return Config{
		ListenAddress: "0.0.0.0:2222", DatabasePath: "/var/lib/sshgatew/sshgatew.db",
		MasterKeyPath: "/var/lib/sshgatew/master.key", HostKeyPath: "/var/lib/sshgatew/ssh_host_ed25519_key",
		IdleTimeout: Duration(30 * time.Minute), DownstreamTimeout: Duration(10 * time.Second),
		MaxSessions: 100, MaxSessionsPerUser: 5, LogLevel: "info", LogFormat: "json",
		OIDC: OIDCConfig{UsernameClaim: "preferred_username", Scopes: []string{"openid", "profile", "email"}, LoginTimeout: Duration(5 * time.Minute)},
	}
}

func ForDataDir(dir string) Config {
	c := Default()
	c.DatabasePath = filepath.Join(dir, "sshgatew.db")
	c.MasterKeyPath = filepath.Join(dir, "master.key")
	c.HostKeyPath = filepath.Join(dir, "ssh_host_ed25519_key")
	return c
}

func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	dec := toml.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := applyOIDCEnvironment(&c); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.ListenAddress); err != nil {
		return fmt.Errorf("invalid listen_address: %w", err)
	}
	if c.DatabasePath == "" || c.MasterKeyPath == "" || c.HostKeyPath == "" {
		return errors.New("database_path, master_key_path, and host_key_path are required")
	}
	if c.IdleTimeout.Value() <= 0 || c.DownstreamTimeout.Value() <= 0 {
		return errors.New("timeouts must be positive")
	}
	if c.MaxSessions <= 0 || c.MaxSessionsPerUser <= 0 || c.MaxSessionsPerUser > c.MaxSessions {
		return errors.New("invalid session limits")
	}
	if c.LogLevel != "debug" && c.LogLevel != "info" && c.LogLevel != "warn" && c.LogLevel != "error" {
		return errors.New("log_level must be debug, info, warn, or error")
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		return errors.New("log_format must be json or text")
	}
	if err := c.OIDC.validate(); err != nil {
		return err
	}
	return nil
}

func (c OIDCConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.IssuerURL == "" || c.ClientID == "" {
		return errors.New("oidc.issuer_url and oidc.client_id are required when OIDC is enabled")
	}
	issuer, err := url.Parse(c.IssuerURL)
	if err != nil || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("oidc.issuer_url must be an absolute issuer URL without a query or fragment")
	}
	if issuer.Scheme != "https" && !(issuer.Scheme == "http" && isLoopbackHost(issuer.Hostname())) {
		return errors.New("oidc.issuer_url must use HTTPS")
	}
	if strings.TrimSpace(c.UsernameClaim) == "" {
		return errors.New("oidc.username_claim is required")
	}
	if c.LoginTimeout.Value() < 30*time.Second || c.LoginTimeout.Value() > 15*time.Minute {
		return errors.New("oidc.login_timeout must be between 30s and 15m")
	}
	hasOpenID := false
	for _, scope := range c.Scopes {
		if strings.TrimSpace(scope) == "" || len(strings.Fields(scope)) != 1 {
			return errors.New("oidc.scopes must contain non-empty values without whitespace")
		}
		if scope == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		return errors.New("oidc.scopes must include openid")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func applyOIDCEnvironment(c *Config) error {
	if value, ok := nonEmptyEnvironment("SSHGATEW_OIDC_ENABLED"); ok {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("SSHGATEW_OIDC_ENABLED must be true or false: %w", err)
		}
		c.OIDC.Enabled = enabled
	}
	if value, ok := nonEmptyEnvironment("SSHGATEW_OIDC_ISSUER"); ok {
		c.OIDC.IssuerURL = strings.TrimSpace(value)
	}
	if value, ok := nonEmptyEnvironment("SSHGATEW_OIDC_CLIENT_ID"); ok {
		c.OIDC.ClientID = value
	}
	if value, ok := nonEmptyEnvironment("SSHGATEW_OIDC_CLIENT_SECRET"); ok {
		c.OIDC.ClientSecret = value
	}
	if value, ok := nonEmptyEnvironment("SSHGATEW_OIDC_USERNAME_CLAIM"); ok {
		c.OIDC.UsernameClaim = strings.TrimSpace(value)
	}
	if value, ok := nonEmptyEnvironment("SSHGATEW_OIDC_SCOPES"); ok {
		c.OIDC.Scopes = strings.Fields(strings.ReplaceAll(value, ",", " "))
	}
	if value, ok := nonEmptyEnvironment("SSHGATEW_OIDC_LOGIN_TIMEOUT"); ok {
		timeout, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid SSHGATEW_OIDC_LOGIN_TIMEOUT: %w", err)
		}
		c.OIDC.LoginTimeout = Duration(timeout)
	}
	return nil
}

func nonEmptyEnvironment(name string) (string, bool) {
	value, ok := os.LookupEnv(name)
	return value, ok && strings.TrimSpace(value) != ""
}

func Write(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := toml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}
