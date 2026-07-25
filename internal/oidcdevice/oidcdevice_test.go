package oidcdevice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type testProvider struct {
	server   *httptest.Server
	private  *rsa.PrivateKey
	username string
	audience string
	secret   string
}

func newTestProvider(t *testing.T) *testProvider {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := &testProvider{private: private, username: "alice", audience: "sshgatew-test", secret: "client-secret"}
	mux := http.NewServeMux()
	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)
	mux.HandleFunc("/.well-known/openid-configuration", provider.discovery)
	mux.HandleFunc("/device", provider.device)
	mux.HandleFunc("/token", provider.token)
	mux.HandleFunc("/keys", provider.keys)
	return provider
}

func (p *testProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.server.URL,
		"authorization_endpoint":                p.server.URL + "/authorize",
		"device_authorization_endpoint":         p.server.URL + "/device",
		"token_endpoint":                        p.server.URL + "/token",
		"jwks_uri":                              p.server.URL + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *testProvider) device(w http.ResponseWriter, r *http.Request) {
	clientID, secret, basic := r.BasicAuth()
	validClientAuth := (!basic && p.secret == "") || (basic && clientID == "sshgatew-test" && secret == p.secret)
	if r.Method != http.MethodPost || !validClientAuth ||
		r.FormValue("client_id") != "sshgatew-test" || !strings.Contains(r.FormValue("scope"), "openid") {
		http.Error(w, "bad device request", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{
		"device_code":               "device-secret",
		"user_code":                 "ABCD-1234",
		"verification_uri":          p.server.URL + "/activate",
		"verification_uri_complete": p.server.URL + "/activate?user_code=" + url.QueryEscape("ABCD-1234"),
		"expires_in":                60,
		"interval":                  1,
	})
}

func TestDeviceLoginSupportsPublicClient(t *testing.T) {
	provider := newTestProvider(t)
	provider.secret = ""
	auth := New(Options{
		IssuerURL: provider.server.URL, ClientID: "sshgatew-test",
		UsernameClaim: "preferred_username", Scopes: []string{"openid"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	login, err := auth.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = auth.Complete(ctx, login); err != nil {
		t.Fatal(err)
	}
}

func (p *testProvider) token(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.FormValue("device_code") != "device-secret" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.private}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{"kid": "test-key"}})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: p.server.URL, Subject: "subject-123", Audience: jwt.Audience{p.audience},
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)),
	}).Claims(map[string]any{"preferred_username": p.username}).Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"access_token": "access-secret", "token_type": "Bearer", "expires_in": 60, "id_token": raw})
}

func (p *testProvider) keys(w http.ResponseWriter, _ *http.Request) {
	key := jose.JSONWebKey{Key: &p.private.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}
	writeJSON(w, map[string]any{"keys": []jose.JSONWebKey{key}})
}

func writeJSON(w http.ResponseWriter, value any) {
	writeJSONStatus(w, http.StatusOK, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func TestDeviceLoginVerifiesIDTokenAndUsername(t *testing.T) {
	provider := newTestProvider(t)
	auth := New(Options{
		IssuerURL: provider.server.URL, ClientID: "sshgatew-test",
		ClientSecret: "client-secret", UsernameClaim: "preferred_username", Scopes: []string{"openid", "profile"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	login, err := auth.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if login.UserCode != "ABCD-1234" || login.VerificationURI != provider.server.URL+"/activate" || login.VerificationURIComplete == "" {
		t.Fatalf("unexpected login instructions: %#v", login)
	}
	identity, err := auth.Complete(ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "subject-123" || identity.Username != "alice" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestDeviceLoginRejectsWrongAudience(t *testing.T) {
	provider := newTestProvider(t)
	provider.audience = "some-other-client"
	auth := New(Options{
		IssuerURL: provider.server.URL, ClientID: "sshgatew-test",
		ClientSecret: "client-secret", UsernameClaim: "preferred_username", Scopes: []string{"openid"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	login, err := auth.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = auth.Complete(ctx, login); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected audience validation failure, got %v", err)
	}
}

func TestEndpointSecurityAndDisplaySanitizing(t *testing.T) {
	if err := validateEndpoint("http://identity.example.com/device"); err == nil {
		t.Fatal("accepted an insecure non-loopback endpoint")
	}
	if err := validateEndpoint("http://127.0.0.1:8080/device"); err != nil {
		t.Fatalf("rejected loopback test endpoint: %v", err)
	}
	if got := displayText("AB\x1b[31mCD\n", 128); got != "AB[31mCD" {
		t.Fatalf("control characters were not removed: %q", got)
	}
}
