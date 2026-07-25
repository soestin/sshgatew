package oidcdevice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Options struct {
	IssuerURL, ClientID, ClientSecret, UsernameClaim string
	Scopes                                           []string
}

type Authenticator struct {
	options  Options
	mu       sync.Mutex
	provider *oidc.Provider
}

type Login struct {
	UserCode, VerificationURI, VerificationURIComplete string
	response                                           *oauth2.DeviceAuthResponse
	oauth                                              *oauth2.Config
	verifier                                           *oidc.IDTokenVerifier
}

type Identity struct {
	Subject, Username string
}

func New(options Options) *Authenticator {
	options.UsernameClaim = strings.TrimSpace(options.UsernameClaim)
	options.Scopes = append([]string(nil), options.Scopes...)
	return &Authenticator{options: options}
}

func (a *Authenticator) Begin(ctx context.Context) (Login, error) {
	provider, err := a.discover(ctx)
	if err != nil {
		return Login{}, err
	}
	endpoint := provider.Endpoint()
	if endpoint.DeviceAuthURL == "" {
		return Login{}, errors.New("OIDC provider does not advertise a device authorization endpoint")
	}
	if err = validateEndpoint(endpoint.DeviceAuthURL); err != nil {
		return Login{}, fmt.Errorf("invalid OIDC device authorization endpoint: %w", err)
	}
	if err = validateEndpoint(endpoint.TokenURL); err != nil {
		return Login{}, fmt.Errorf("invalid OIDC token endpoint: %w", err)
	}
	oauthConfig := &oauth2.Config{
		ClientID:     a.options.ClientID,
		ClientSecret: a.options.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       append([]string(nil), a.options.Scopes...),
	}
	response, err := requestDeviceAuth(ctx, oauthConfig)
	if err != nil {
		return Login{}, fmt.Errorf("start OIDC device authorization: %w", err)
	}
	if response.DeviceCode == "" || response.UserCode == "" || response.VerificationURI == "" {
		return Login{}, errors.New("OIDC provider returned an incomplete device authorization response")
	}
	if err = validateEndpoint(response.VerificationURI); err != nil {
		return Login{}, fmt.Errorf("invalid OIDC verification URI: %w", err)
	}
	if response.VerificationURIComplete != "" {
		if err = validateEndpoint(response.VerificationURIComplete); err != nil {
			return Login{}, fmt.Errorf("invalid complete OIDC verification URI: %w", err)
		}
	}
	return Login{
		UserCode:                displayText(response.UserCode, 128),
		VerificationURI:         displayText(response.VerificationURI, 2048),
		VerificationURIComplete: displayText(response.VerificationURIComplete, 2048),
		response:                response,
		oauth:                   oauthConfig,
		verifier:                provider.Verifier(&oidc.Config{ClientID: a.options.ClientID}),
	}, nil
}

func requestDeviceAuth(ctx context.Context, config *oauth2.Config) (*oauth2.DeviceAuthResponse, error) {
	form := url.Values{"client_id": {config.ClientID}}
	if len(config.Scopes) != 0 {
		form.Set("scope", strings.Join(config.Scopes, " "))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Endpoint.DeviceAuthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if config.ClientSecret != "" {
		request.SetBasicAuth(config.ClientID, config.ClientSecret)
	}
	client := http.DefaultClient
	if configured, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = configured
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil, fmt.Errorf("device authorization endpoint returned HTTP %d", response.StatusCode)
	}
	var device oauth2.DeviceAuthResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err = decoder.Decode(&device); err != nil {
		return nil, fmt.Errorf("decode device authorization response: %w", err)
	}
	return &device, nil
}

func (a *Authenticator) Complete(ctx context.Context, login Login) (Identity, error) {
	if login.response == nil || login.oauth == nil || login.verifier == nil {
		return Identity{}, errors.New("invalid OIDC login state")
	}
	token, err := login.oauth.DeviceAccessToken(ctx, login.response)
	if err != nil {
		return Identity{}, fmt.Errorf("complete OIDC device authorization: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, errors.New("OIDC token response did not include an ID token")
	}
	idToken, err := login.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify OIDC ID token: %w", err)
	}
	var claims map[string]any
	if err = idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("read OIDC ID token claims: %w", err)
	}
	value, ok := claims[a.options.UsernameClaim].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return Identity{}, fmt.Errorf("OIDC ID token is missing string claim %q", a.options.UsernameClaim)
	}
	return Identity{Subject: idToken.Subject, Username: strings.ToLower(strings.TrimSpace(value))}, nil
}

func (a *Authenticator) discover(ctx context.Context) (*oidc.Provider, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.provider != nil {
		return a.provider, nil
	}
	provider, err := oidc.NewProvider(ctx, a.options.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err = provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("read OIDC provider metadata: %w", err)
	}
	if err = validateEndpoint(metadata.JWKSURL); err != nil {
		return nil, fmt.Errorf("invalid OIDC JWKS endpoint: %w", err)
	}
	a.provider = provider
	return provider, nil
}

func validateEndpoint(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("endpoint must be an absolute URL without user information or a fragment")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopback(parsed.Hostname()) {
		return nil
	}
	return errors.New("endpoint must use HTTPS")
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func displayText(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
