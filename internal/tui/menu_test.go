package tui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
	"sshgatew/internal/totp"
)

func testModel(t *testing.T) (*Model, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	u, err := st.AddUser(context.Background(), "admin", store.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.AddGatewayKey(context.Background(), u.Username, "SHA256:test", "key", "test"); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "master")
	if err = secrets.Generate(keyPath); err != nil {
		t.Fatal(err)
	}
	cipher, err := secrets.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return New(context.Background(), st, cipher, time.Second, "127.0.0.1:1234", u, ""), st
}
func TestSecretIsNeverRendered(t *testing.T) {
	m, _ := testModel(t)
	m.mode = "secret_password"
	m.input = "do-not-display-this"
	view := m.View().Content
	if strings.Contains(view, m.input) {
		t.Fatal("secret rendered")
	}
	if !strings.Contains(strings.ToLower(view), "never rendered") {
		t.Fatal("missing hidden-input indicator")
	}
}
func TestHelpDoesNotMutate(t *testing.T) {
	m, _ := testModel(t)
	if cmd := m.runCommand("help"); cmd != nil {
		t.Fatal("help unexpectedly asynchronous")
	}
	if m.mode != "help" {
		t.Fatal("help mode not opened")
	}
}

func TestViewStaysInsideTerminal(t *testing.T) {
	m, _ := testModel(t)
	for i := 0; i < 80; i++ {
		m.targets = append(m.targets, store.Target{Name: fmt.Sprintf("very-long-production-target-%03d", i), Host: "host-with-an-extremely-long-name.internal.example", Port: 22, RemoteUsername: "deployment-user"})
	}
	states := []func(){
		func() { m.mode, m.form, m.actions = "", nil, nil },
		func() {
			m.mode = "form"
			m.form = &adminForm{title: "Add target", fields: []formField{{label: "Name", value: "production"}, {label: "Host", value: "host.internal.example"}, {label: "Authentication", value: "private_key", options: []string{"private_key", "password"}}}}
		},
		func() {
			m.mode, m.actions = "actions", []actionItem{{"Connect", "connect"}, {"Replace credential", "credential"}, {"Delete", "delete"}}
		},
	}
	for _, state := range states {
		state()
		for _, size := range []struct{ w, h int }{{20, 8}, {40, 10}, {60, 16}, {120, 30}} {
			m.width, m.height = size.w, size.h
			lines := strings.Split(m.View().Content, "\n")
			if len(lines) > size.h {
				t.Fatalf("%dx%d: rendered %d lines", size.w, size.h, len(lines))
			}
			for n, line := range lines {
				if width := ansi.StringWidth(line); width > size.w {
					t.Fatalf("%dx%d line %d is %d cells: %q", size.w, size.h, n, width, line)
				}
			}
		}
	}
}

func TestSearchIsExplicitAndPageNavigationClamps(t *testing.T) {
	m, _ := testModel(t)
	m.targets = []store.Target{{Name: "alpha"}, {Name: "beta"}}
	m.height = 9
	m.handleKey("x")
	if m.query != "" {
		t.Fatal("typing outside search changed filter")
	}
	m.handleKey("/")
	m.handleKey("b")
	if m.query != "b" || !m.searching {
		t.Fatal("search input failed")
	}
	m.handleKey("enter")
	if m.searching {
		t.Fatal("search did not close")
	}
	m.handleKey("pgdown")
	if m.cursor >= m.itemCount() {
		t.Fatal("page navigation escaped list")
	}
}

func TestPrivateKeyControlDSavesTargetAndReturnsToTargets(t *testing.T) {
	m, st := testModel(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateBlock, err := gossh.MarshalPrivateKey(privateKey, "test")
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	m.section = "audit"
	m.mode = "secret_key"
	m.input = string(pem.EncodeToMemory(privateBlock))
	m.pending = &pendingOperation{
		kind: "target_add", name: "control-d-test", host: "127.0.0.1", port: 22,
		remote: "root", credentialKind: store.CredentialPrivateKey, hostKey: hostKey,
	}

	cmd := m.handleKey("ctrl+d")
	if cmd == nil {
		t.Fatal("Ctrl+D did not start credential save")
	}
	msg := cmd()
	if _, reload := m.Update(msg); reload == nil {
		t.Fatal("credential save did not request a reload")
	}
	if m.section != "targets" || m.status != "Target added and credential saved." {
		t.Fatalf("section=%q status=%q", m.section, m.status)
	}
	target, err := st.TargetByName(context.Background(), "control-d-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Nonce) == 0 || len(target.Ciphertext) == 0 {
		t.Fatal("encrypted credential was not stored")
	}
}

func TestForwardedAgentPublicKeySavesWithoutPrivateMaterial(t *testing.T) {
	m, st := testModel(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	m.section = "audit"
	m.mode = "agent_key"
	m.input = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPublic))) + " yubikey-test"
	m.pending = &pendingOperation{
		kind: "target_add", name: "agent-test", host: "127.0.0.1", port: 22,
		remote: "root", credentialKind: store.CredentialAgent, hostKey: sshPublic,
	}
	applyCommand(m, m.handleKey("enter"))
	target, err := st.TargetByName(context.Background(), "agent-test")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := m.cipher.Decrypt(target.ID, target.CredentialKind, target.Nonce, target.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.PublicKey) == 0 || len(payload.PrivateKey) != 0 || payload.Password != "" {
		t.Fatalf("unexpected forwarded-agent payload: %#v", payload)
	}
	if m.section != "targets" || m.status != "Target added and credential saved." {
		t.Fatalf("section=%q status=%q", m.section, m.status)
	}
}

func TestSecurityKeyPublicIdentityIsAcceptedForForwardedAgent(t *testing.T) {
	const yubikey = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAOdpU8BsAjXH/yTiCCi9GUqE6J6utSVpOUrxQ16kxjFAAAABHNzaDo= yubikey1"
	m, st := testModel(t)
	publicKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(yubikey))
	if err != nil {
		t.Fatal(err)
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := gossh.NewPublicKey(hostPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	m.mode, m.input = "agent_key", yubikey
	m.pending = &pendingOperation{kind: "target_add", name: "yubikey", host: "127.0.0.1", port: 22, remote: "root", credentialKind: store.CredentialAgent, hostKey: hostKey}
	applyCommand(m, m.handleKey("enter"))
	target, err := st.TargetByName(context.Background(), "yubikey")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := m.cipher.Decrypt(target.ID, target.CredentialKind, target.Nonce, target.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	stored, _, _, _, err := gossh.ParseAuthorizedKey(payload.PublicKey)
	if err != nil || stored.Type() != "sk-ssh-ed25519@openssh.com" {
		t.Fatalf("stored key type=%v err=%v", stored, err)
	}
	if gossh.FingerprintSHA256(stored) != gossh.FingerprintSHA256(publicKey) {
		t.Fatal("security-key identity changed while storing")
	}
}

func TestGenerateReusableSSHKeyAndSelectItForTarget(t *testing.T) {
	m, st := testModel(t)
	m.section = "keys"
	m.openAddForm()
	m.form.fields[0].value = "production"
	m.form.fields[1].value = "generate_ed25519"
	applyCommand(m, m.submitForm())

	identities, err := st.ListSSHIdentities(context.Background())
	if err != nil || len(identities) != 1 {
		t.Fatalf("identities=%#v err=%v", identities, err)
	}
	identity := identities[0]
	payload, err := m.cipher.DecryptSSHIdentity(identity.ID, identity.Nonce, identity.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.ParsePrivateKey(payload.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if gossh.FingerprintSHA256(signer.PublicKey()) != identity.Fingerprint {
		t.Fatal("generated private key does not match stored public key")
	}

	applyMessage(m, reloadMsg{})
	m.section = "targets"
	m.openAddForm()
	if len(m.form.fields) != 5 {
		t.Fatalf("saved key shown for private-key authentication: %#v", m.form.fields)
	}
	m.form.fields[4].value = store.CredentialStoredKey
	m.syncFormOptions()
	if got := m.form.fields[5].value; got != identity.Name {
		t.Fatalf("saved key was not selected in target form: %q", got)
	}
	m.form.fields[4].value = store.CredentialPassword
	m.syncFormOptions()
	if len(m.form.fields) != 5 {
		t.Fatalf("saved key remained visible for password authentication: %#v", m.form.fields)
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := gossh.NewPublicKey(hostPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	m.pending = &pendingOperation{kind: "target_add", name: "production-host", host: "127.0.0.1", port: 22, remote: "root", credentialKind: store.CredentialStoredKey, identity: identity, identityID: identity.ID, hostKey: hostKey}
	applyCommand(m, m.finishStoredTarget())
	target, err := st.TargetByName(context.Background(), "production-host")
	if err != nil {
		t.Fatal(err)
	}
	if target.IdentityID == nil || *target.IdentityID != identity.ID || len(target.Ciphertext) != 0 {
		t.Fatalf("target did not reference reusable key cleanly: %#v", target)
	}
}

func TestTOTPEnrollmentQRAndReplayProtectedChallenge(t *testing.T) {
	m, st := testModel(t)
	applyMessage(m, reloadMsg{})
	m.section = "users"
	for i, user := range m.users {
		if user.Username == "admin" {
			m.cursor = i
		}
	}
	m.openSelectedActions()
	for i, action := range m.actions {
		if action.code == "user_totp_setup" {
			m.actionCursor = i
		}
	}
	m.dispatchAction("user_totp_setup")
	if m.mode != "totp_enroll" || len(m.pending.totpQR) == 0 {
		t.Fatal("TOTP QR enrollment did not open")
	}
	m.width, m.height = 80, 24
	if view := m.View().Content; strings.Contains(view, m.pending.totpSecret) || !strings.Contains(view, "TOTP enrollment") || !strings.Contains(view, "Enter continue") {
		t.Fatal("QR screen leaked the fallback secret or omitted its title/instructions")
	}
	secret := m.pending.totpSecret
	code, _, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m.mode, m.input = "totp_confirm", code
	applyCommand(m, m.finishTOTPEnrollment())
	u, err := st.UserByName(context.Background(), "admin")
	if err != nil || !u.TOTPEnabled {
		t.Fatalf("user=%#v err=%v", u, err)
	}

	challenge := NewTOTPChallenge(context.Background(), st, m.cipher, "127.0.0.1", u)
	challenge.input = code
	challenge.verifyTOTPChallenge()
	if challenge.result != nil && challenge.result.Verified {
		t.Fatal("enrollment code was reusable for authentication")
	}
	freshTime := time.Now().Add(30 * time.Second)
	fresh, _, err := totp.Code(secret, freshTime)
	if err != nil {
		t.Fatal(err)
	}
	// Validation accepts the adjacent window, allowing this deterministic test
	// without waiting for the wall clock to advance.
	challenge.input = fresh
	challenge.verifyTOTPChallenge()
	if challenge.result == nil || !challenge.result.Verified {
		t.Fatal("fresh TOTP code was rejected")
	}
}

func TestAdminMenusManageUsersGroupsKeysAndGrants(t *testing.T) {
	m, st := testModel(t)
	applyMessage(m, reloadMsg{})

	m.section = "users"
	m.handleKey("a")
	typeKeys(m, "alice")
	m.handleKey("tab")
	applyCommand(m, m.handleKey("enter"))
	if _, err := st.UserByName(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}

	applyMessage(m, reloadMsg{})
	m.section = "groups"
	m.handleKey("a")
	typeKeys(m, "operators")
	applyCommand(m, m.handleKey("enter"))
	applyMessage(m, reloadMsg{})
	m.section, m.cursor = "groups", 0
	m.handleKey("enter") // group actions
	m.handleKey("enter") // add member
	for i, action := range m.actions {
		if action.code == "alice" {
			m.actionCursor = i
		}
	}
	applyCommand(m, m.handleKey("enter"))
	members, err := st.ListGroupMembers(context.Background())
	if err != nil || len(members) != 1 || members[0].Username != "alice" {
		t.Fatalf("members=%#v err=%v", members, err)
	}

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gatewayKey, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	applyMessage(m, reloadMsg{})
	m.section = "users"
	for i, user := range m.users {
		if user.Username == "alice" {
			m.cursor = i
		}
	}
	m.handleKey("enter")
	m.handleKey("enter") // Add SSH key
	m.Update(tea.PasteMsg{Content: strings.TrimSpace(string(gossh.MarshalAuthorizedKey(gatewayKey)))})
	applyCommand(m, m.handleKey("enter"))
	keys, err := st.ListGatewayKeys(context.Background(), "alice")
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%#v err=%v", keys, err)
	}

	hostKey, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.AddTarget(context.Background(), store.NewTarget{Name: "prod", Host: "127.0.0.1", Port: 22, RemoteUsername: "root", CredentialKind: store.CredentialPrivateKey, HostKeyAlgorithm: hostKey.Type(), HostPublicKey: strings.TrimSpace(string(gossh.MarshalAuthorizedKey(hostKey)))}); err != nil {
		t.Fatal(err)
	}
	applyMessage(m, reloadMsg{})
	m.section = "grants"
	m.handleKey("a")
	m.handleKey("tab")
	m.handleKey("tab")
	for m.form.fields[2].value != "alice" {
		m.handleKey("right")
	}
	for m.form.index < len(m.form.fields)-1 {
		m.handleKey("tab")
	}
	applyCommand(m, m.handleKey("enter"))
	grants, err := st.ListGrants(context.Background())
	if err != nil || len(grants) != 1 || grants[0].Principal != "alice" {
		t.Fatalf("grants=%#v err=%v", grants, err)
	}
}

func TestAdminCommandPaletteIsNotExposed(t *testing.T) {
	m, _ := testModel(t)
	m.handleKey(":")
	if m.mode != "" {
		t.Fatalf("colon opened obsolete mode %q", m.mode)
	}
}

func typeKeys(m *Model, value string) {
	for _, r := range value {
		m.handleKey(string(r))
	}
}
