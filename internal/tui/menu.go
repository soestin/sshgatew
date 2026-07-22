package tui

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	gossh "golang.org/x/crypto/ssh"

	"sshgatew/internal/downstream"
	"sshgatew/internal/secrets"
	"sshgatew/internal/store"
	"sshgatew/internal/totp"
)

type Result struct {
	TargetID int64
	Quit     bool
	Verified bool
}

type pendingOperation struct {
	kind, name, host, remote, credentialKind  string
	username, group, principalKind, principal string
	port                                      int
	target                                    store.Target
	user                                      store.User
	grant                                     store.Grant
	forwardRule                               store.ForwardRule
	identity                                  store.SSHIdentity
	identityID                                int64
	privateKey                                []byte
	hostKey                                   gossh.PublicKey
	totpSecret, totpURI                       string
	totpQR                                    []string
}

type formField struct {
	label   string
	value   string
	options []string
}

type adminForm struct {
	kind, title string
	fields      []formField
	index       int
}

type actionItem struct{ label, code string }

type Model struct {
	ctx                   context.Context
	store                 *store.Store
	cipher                *secrets.Cipher
	timeout               time.Duration
	user                  store.User
	sourceAddress         string
	targets               []store.Target
	cursor, width, height int
	query, status         string
	result                *Result
	section               string
	users                 []store.User
	groups                []store.Group
	groupMembers          []store.GroupMember
	identities            []store.SSHIdentity
	grants                []store.Grant
	forwardRules          []store.ForwardRule
	auditEvents           []store.AuditEvent
	mode, input           string
	searching             bool
	pending               *pendingOperation
	form                  *adminForm
	actions               []actionItem
	actionCursor          int
	totpAttempts          int
}

func New(ctx context.Context, s *store.Store, cipher *secrets.Cipher, timeout time.Duration, sourceAddress string, u store.User, status string) *Model {
	return &Model{ctx: ctx, store: s, cipher: cipher, timeout: timeout, sourceAddress: sourceAddress, user: u, status: status, section: "targets"}
}
func NewTOTPChallenge(ctx context.Context, s *store.Store, cipher *secrets.Cipher, sourceAddress string, u store.User) *Model {
	return &Model{ctx: ctx, store: s, cipher: cipher, sourceAddress: sourceAddress, user: u, section: "targets", mode: "totp_auth", status: "Enter the current code from your authenticator app."}
}
func (m *Model) Result() Result {
	if m.result == nil {
		return Result{Quit: true}
	}
	return *m.result
}
func (m *Model) Init() tea.Cmd { return func() tea.Msg { return reloadMsg{} } }

type reloadMsg struct{}
type dataMsg struct {
	targets      []store.Target
	users        []store.User
	groups       []store.Group
	groupMembers []store.GroupMember
	identities   []store.SSHIdentity
	grants       []store.Grant
	forwardRules []store.ForwardRule
	auditEvents  []store.AuditEvent
	err          error
}
type hostKeyMsg struct {
	key gossh.PublicKey
	err error
}
type mutationMsg struct {
	status  string
	section string
	err     error
}

func (m *Model) load() tea.Msg {
	var ts []store.Target
	var e error
	if m.user.Role == store.RoleAdmin {
		ts, e = m.store.ListTargets(m.ctx)
	} else {
		ts, e = m.store.ListAuthorizedTargets(m.ctx, m.user)
	}
	if e != nil {
		return dataMsg{err: e}
	}
	d := dataMsg{targets: ts}
	if m.user.Role == store.RoleAdmin {
		d.users, d.err = m.store.ListUsers(m.ctx)
		if d.err == nil {
			d.groups, d.err = m.store.ListGroups(m.ctx)
		}
		if d.err == nil {
			d.identities, d.err = m.store.ListSSHIdentities(m.ctx)
		}
		if d.err == nil {
			d.groupMembers, d.err = m.store.ListGroupMembers(m.ctx)
		}
		if d.err == nil {
			d.grants, d.err = m.store.ListGrants(m.ctx)
		}
		if d.err == nil {
			d.forwardRules, d.err = m.store.ListForwardRules(m.ctx)
		}
		if d.err == nil {
			d.auditEvents, d.err = m.store.ListAudit(m.ctx, 50)
		}
	}
	return d
}
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case reloadMsg:
		return m, m.load
	case dataMsg:
		m.targets, m.users, m.groups, m.groupMembers, m.identities, m.grants, m.forwardRules, m.auditEvents = v.targets, v.users, v.groups, v.groupMembers, v.identities, v.grants, v.forwardRules, v.auditEvents
		if v.err != nil {
			m.status = v.err.Error()
		}
		m.clamp()
		return m, nil
	case hostKeyMsg:
		if v.err != nil {
			m.mode = ""
			m.pending = nil
			m.status = "Host-key scan failed: " + v.err.Error()
			return m, nil
		}
		m.pending.hostKey = v.key
		m.mode = "confirm_host"
		m.status = "Verify out-of-band: " + v.key.Type() + " " + gossh.FingerprintSHA256(v.key) + ". Press y to accept or n to cancel."
		return m, nil
	case mutationMsg:
		m.mode = ""
		m.input = ""
		m.pending = nil
		m.form, m.actions = nil, nil
		m.actionCursor = 0
		if v.err != nil {
			m.status = "Admin operation failed: " + v.err.Error()
		} else {
			m.status = v.status
			if v.section != "" {
				m.section = v.section
				m.cursor = 0
			}
		}
		return m, m.load
	case tea.PasteMsg:
		if m.mode == "secret_key" {
			m.input += v.Content
		} else if m.mode == "public_key" || m.mode == "agent_key" {
			m.input += strings.TrimSpace(v.Content)
		} else if m.mode == "form" && m.form != nil && len(m.form.fields[m.form.index].options) == 0 {
			m.form.fields[m.form.index].value += strings.TrimSpace(v.Content)
		}
		return m, nil
	case tea.WindowSizeMsg:
		m.width, m.height = v.Width, v.Height
		return m, nil
	case tea.KeyPressMsg:
		return m, m.handleKey(v.Keystroke())
	}
	return m, nil
}

func (m *Model) handleKey(key string) tea.Cmd {
	if m.mode != "" {
		return m.handleModeKey(key)
	}
	if m.searching {
		switch key {
		case "esc":
			m.searching, m.query, m.cursor = false, "", 0
		case "enter":
			m.searching = false
		case "backspace":
			m.query, m.cursor = removeLastRune(m.query), 0
		case "ctrl+u":
			m.query, m.cursor = "", 0
		case "space":
			m.query, m.cursor = m.query+" ", 0
		default:
			if len([]rune(key)) == 1 {
				m.query, m.cursor = m.query+key, 0
			}
		}
		return nil
	}
	if key == "ctrl+c" || key == "q" {
		m.result = &Result{Quit: true}
		return tea.Quit
	}
	if m.user.Role == store.RoleAdmin {
		switch key {
		case "1":
			m.section = "targets"
			m.cursor = 0
		case "2":
			m.section = "keys"
			m.cursor = 0
		case "3":
			m.section = "users"
			m.cursor = 0
		case "4":
			m.section = "groups"
			m.cursor = 0
		case "5":
			m.section = "grants"
			m.cursor = 0
		case "6":
			m.section = "forwards"
			m.cursor = 0
		case "7":
			m.section = "audit"
			m.cursor = 0
		case "r":
			return m.load
		case "a":
			return m.openAddForm()
		case "m":
			return m.openSelectedActions()
		case "left", "h":
			m.changeSection(-1)
		case "right", "l", "tab":
			m.changeSection(1)
		}
	}
	switch key {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < m.itemCount()-1 {
			m.cursor++
		}
	case "pgup":
		m.cursor -= m.pageSize()
		if m.cursor < 0 {
			m.cursor = 0
		}
	case "pgdown":
		m.cursor += m.pageSize()
		m.clamp()
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		if n := m.itemCount(); n > 0 {
			m.cursor = n - 1
		}
	case "/":
		if m.section == "targets" {
			m.searching = true
			m.status = ""
		}
	case "esc":
		if m.section == "targets" {
			m.query, m.cursor = "", 0
		}
	case "?":
		m.mode = "help"
	case "enter":
		if m.section == "targets" {
			f := m.filtered()
			if len(f) > 0 {
				m.result = &Result{TargetID: f[m.cursor].ID}
				return tea.Quit
			}
		} else if m.user.Role == store.RoleAdmin && m.section != "audit" {
			return m.openSelectedActions()
		}
	}
	return nil
}
func (m *Model) handleModeKey(key string) tea.Cmd {
	if m.mode == "help" {
		m.mode = ""
		return nil
	}
	switch m.mode {
	case "totp_auth":
		if key == "enter" {
			m.verifyTOTPChallenge()
			return nil
		}
		if key == "esc" || key == "ctrl+c" {
			m.result = &Result{Quit: true}
			return tea.Quit
		}
	case "totp_enroll":
		if key == "enter" {
			m.mode, m.input = "totp_confirm", ""
			m.status = "Enter a current code to verify enrollment."
			return nil
		}
	case "totp_confirm":
		if key == "enter" {
			return m.finishTOTPEnrollment()
		}
	case "form":
		return m.handleFormKey(key)
	case "actions", "key_remove", "member_add", "member_remove":
		return m.handleActionKey(key)
	case "identity_public":
		m.closeModal("")
		return nil
	case "confirm_delete":
		if key == "y" {
			return m.finishDelete()
		}
		if key == "n" {
			m.closeModal("Cancelled.")
		}
		return nil
	case "public_key":
		if key == "enter" || key == "ctrl+d" {
			return m.finishPublicKey()
		}
	case "agent_key":
		if key == "enter" || key == "ctrl+d" {
			return m.finishAgentKey()
		}
	}
	if key == "esc" {
		m.closeModal("Cancelled.")
		return nil
	}
	switch m.mode {
	case "confirm_host":
		if key == "n" {
			m.mode = ""
			m.pending = nil
			m.status = "Host key rejected."
		} else if key == "y" {
			if m.pending.kind == "host_key" {
				return m.finishHostKey()
			} else if m.pending.credentialKind == store.CredentialPassword {
				m.mode = "secret_password"
				m.input = ""
				m.status = "Enter downstream password (hidden), then press Enter."
			} else if m.pending.credentialKind == store.CredentialPrivateKey {
				m.mode = "secret_key"
				m.input = ""
				m.status = "Paste the private key; its contents will not be rendered. Press Ctrl+D when complete."
			} else if m.pending.credentialKind == store.CredentialStoredKey {
				return m.finishStoredTarget()
			} else {
				m.mode = "agent_key"
				m.input = ""
				m.status = "Paste the public key that must be present in the forwarded agent."
			}
		}
		return nil
	case "secret_password":
		if key == "enter" {
			return m.finishCredential(secrets.Payload{Password: m.input})
		}
	case "secret_key":
		if key == "ctrl+d" {
			keyBytes := []byte(m.input)
			_, err := gossh.ParsePrivateKey(keyBytes)
			if err == nil {
				if m.pending.kind == "identity_add" {
					return m.finishIdentity(keyBytes)
				}
				return m.finishCredential(secrets.Payload{PrivateKey: keyBytes})
			}
			var missing *gossh.PassphraseMissingError
			if errors.As(err, &missing) {
				m.pending.privateKey = keyBytes
				m.mode = "secret_passphrase"
				m.input = ""
				m.status = "Encrypted key received. Enter its passphrase (hidden), then press Enter."
				return nil
			}
			m.status = "Invalid private key: " + err.Error()
			m.input = ""
			return nil
		}
		if key == "enter" {
			m.input += "\n"
			return nil
		}
	case "secret_passphrase":
		if key == "enter" {
			keyBytes := m.pending.privateKey
			if _, err := gossh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(m.input)); err != nil {
				m.status = "Invalid passphrase: " + err.Error()
				m.input = ""
				return nil
			}
			if m.pending.kind == "identity_add" {
				return m.finishIdentityWithPassphrase(keyBytes, m.input)
			}
			return m.finishCredential(secrets.Payload{PrivateKey: keyBytes, Passphrase: m.input})
		}
	}
	if key == "backspace" {
		if len(m.input) > 0 {
			m.input = removeLastRune(m.input)
		}
		return nil
	}
	if key == "space" {
		m.input += " "
		return nil
	}
	if len([]rune(key)) == 1 {
		m.input += key
	}
	return nil
}
func removeLastRune(v string) string {
	r := []rune(v)
	if len(r) == 0 {
		return v
	}
	return string(r[:len(r)-1])
}

func (m *Model) closeModal(status string) {
	m.mode, m.input = "", ""
	m.form, m.actions, m.pending = nil, nil, nil
	m.actionCursor = 0
	m.status = status
}

func (m *Model) openAddForm() tea.Cmd {
	if m.user.Role != store.RoleAdmin {
		return nil
	}
	switch m.section {
	case "targets":
		m.form = &adminForm{kind: "target_add", title: "Add target", fields: []formField{{label: "Name"}, {label: "Host"}, {label: "Port", value: "22"}, {label: "Remote user"}, {label: "Authentication", value: store.CredentialPrivateKey, options: credentialKinds()}}}
	case "keys":
		m.form = &adminForm{kind: "identity_add", title: "Add SSH key", fields: []formField{{label: "Name"}, {label: "Method", value: "generate_ed25519", options: []string{"generate_ed25519", "import_private_key"}}}}
	case "users":
		m.form = &adminForm{kind: "user_add", title: "Add user", fields: []formField{{label: "Username"}, {label: "Role", value: store.RoleMember, options: []string{store.RoleMember, store.RoleAdmin}}}}
	case "groups":
		m.form = &adminForm{kind: "group_add", title: "Add group", fields: []formField{{label: "Name"}}}
	case "grants":
		if len(m.targets) == 0 || len(m.users)+len(m.groups) == 0 {
			m.status = "Add a target and a user or group before creating access."
			return nil
		}
		m.form = &adminForm{kind: "grant_add", title: "Add access grant", fields: []formField{{label: "Target", value: m.targets[0].Name, options: targetNames(m.targets)}, {label: "Principal type", value: "user", options: []string{"user", "group"}}, {label: "Principal", value: firstUser(m.users), options: userNames(m.users)}, {label: "Shell", value: "yes", options: []string{"yes", "no"}}, {label: "SFTP", value: "yes", options: []string{"yes", "no"}}, {label: "Legacy SCP", value: "yes", options: []string{"yes", "no"}}, {label: "TCP forwarding", value: "no", options: []string{"no", "yes"}}}}
	case "forwards":
		if len(m.targets) == 0 {
			m.status = "Add a target before creating a forwarding rule."
			return nil
		}
		m.form = &adminForm{kind: "forward_add", title: "Allow TCP destination", fields: []formField{{label: "Target", value: m.targets[0].Name, options: targetNames(m.targets)}, {label: "Destination host"}, {label: "Destination port"}}}
	default:
		m.status = "This section is read-only."
		return nil
	}
	m.mode = "form"
	m.status = "Complete the fields, then save."
	return nil
}

func (m *Model) openSelectedActions() tea.Cmd {
	m.actionCursor = 0
	switch m.section {
	case "targets":
		rows := m.filtered()
		if len(rows) == 0 {
			m.status = "No target selected."
			return nil
		}
		m.pending = &pendingOperation{target: rows[m.cursor]}
		state := "Disable"
		if !rows[m.cursor].Enabled {
			state = "Enable"
		}
		m.actions = []actionItem{{"Edit connection", "target_edit"}, {"Replace credential", "target_credential"}, {"Replace host key", "target_host_key"}, {state, "target_toggle"}, {"Delete", "target_delete"}}
		if rows[m.cursor].Enabled {
			m.actions = append([]actionItem{{"Connect", "target_connect"}}, m.actions...)
		}
	case "users":
		if len(m.users) == 0 {
			m.status = "No user selected."
			return nil
		}
		u := m.users[m.cursor]
		m.pending = &pendingOperation{user: u, username: u.Username}
		role := "Make administrator"
		if u.Role == store.RoleAdmin {
			role = "Make member"
		}
		state := "Disable"
		if !u.Enabled {
			state = "Enable"
		}
		totpAction := actionItem{"Set up TOTP", "user_totp_setup"}
		if u.TOTPEnabled {
			totpAction = actionItem{"Remove TOTP", "user_totp_remove"}
		}
		m.actions = []actionItem{{"Add SSH key", "user_key_add"}, {"Remove SSH key", "user_key_remove"}, totpAction, {role, "user_role"}, {state, "user_toggle"}, {"Delete", "user_delete"}}
	case "keys":
		if len(m.identities) == 0 {
			m.status = "No SSH key selected."
			return nil
		}
		m.pending = &pendingOperation{identity: m.identities[m.cursor]}
		m.actions = []actionItem{{"View public key", "identity_view"}, {"Delete", "identity_delete"}}
	case "groups":
		if len(m.groups) == 0 {
			m.status = "No group selected."
			return nil
		}
		m.pending = &pendingOperation{group: m.groups[m.cursor].Name}
		m.actions = []actionItem{{"Add member", "group_member_add"}, {"Remove member", "group_member_remove"}, {"Delete", "group_delete"}}
	case "grants":
		if len(m.grants) == 0 {
			m.status = "No grant selected."
			return nil
		}
		m.pending = &pendingOperation{grant: m.grants[m.cursor]}
		m.actions = []actionItem{{"Edit capabilities", "grant_edit"}, {"Remove access", "grant_delete"}}
	case "forwards":
		if len(m.forwardRules) == 0 {
			m.status = "No forwarding rule selected."
			return nil
		}
		m.pending = &pendingOperation{forwardRule: m.forwardRules[m.cursor]}
		m.actions = []actionItem{{"Delete destination", "forward_delete"}}
	default:
		return nil
	}
	m.mode = "actions"
	return nil
}

func (m *Model) handleActionKey(key string) tea.Cmd {
	if key == "esc" {
		m.closeModal("Cancelled.")
		return nil
	}
	switch key {
	case "up", "k":
		if m.actionCursor > 0 {
			m.actionCursor--
		}
	case "down", "j", "tab":
		if m.actionCursor < len(m.actions)-1 {
			m.actionCursor++
		}
	case "home":
		m.actionCursor = 0
	case "end":
		if len(m.actions) > 0 {
			m.actionCursor = len(m.actions) - 1
		}
	case "enter", "space":
		if len(m.actions) > 0 {
			code := m.actions[m.actionCursor].code
			if m.mode == "key_remove" || m.mode == "member_add" || m.mode == "member_remove" {
				code = m.mode
			}
			return m.dispatchAction(code)
		}
	}
	return nil
}

func (m *Model) dispatchAction(code string) tea.Cmd {
	p := m.pending
	switch code {
	case "target_connect":
		m.result = &Result{TargetID: p.target.ID}
		return tea.Quit
	case "grant_edit":
		g := p.grant
		yesNo := func(v bool) string {
			if v {
				return "yes"
			}
			return "no"
		}
		m.form = &adminForm{kind: "grant_edit", title: "Edit " + g.Principal + " → " + g.Target, fields: []formField{{label: "Shell", value: yesNo(g.Shell), options: []string{"yes", "no"}}, {label: "SFTP", value: yesNo(g.SFTP), options: []string{"yes", "no"}}, {label: "Legacy SCP", value: yesNo(g.SCP), options: []string{"yes", "no"}}, {label: "TCP forwarding", value: yesNo(g.TCPForward), options: []string{"yes", "no"}}}}
		m.mode = "form"
	case "target_edit":
		m.form = &adminForm{kind: "target_edit", title: "Edit " + p.target.Name, fields: []formField{{label: "Host", value: p.target.Host}, {label: "Port", value: strconv.Itoa(p.target.Port)}, {label: "Remote user", value: p.target.RemoteUsername}}}
		m.mode = "form"
	case "target_credential":
		m.form = &adminForm{kind: "target_credential", title: "Replace credential", fields: []formField{{label: "Authentication", value: p.target.CredentialKind, options: credentialKinds()}}}
		m.syncTargetKeyField()
		m.mode = "form"
	case "target_host_key":
		p.kind = "host_key"
		return m.scanHost(net.JoinHostPort(p.target.Host, strconv.Itoa(p.target.Port)))
	case "target_toggle":
		enabled := !p.target.Enabled
		return m.mutate("targets", "Target updated.", "admin.target."+enabledWord(enabled), map[string]any{"target": p.target.Name}, func() error { return m.store.SetTargetEnabled(m.ctx, p.target.Name, enabled) })
	case "target_delete", "user_delete", "group_delete", "grant_delete", "forward_delete", "identity_delete", "user_totp_remove":
		p.kind = code
		m.mode = "confirm_delete"
	case "identity_view":
		m.mode = "identity_public"
	case "user_key_add":
		m.mode, m.input = "public_key", ""
		m.status = "Paste an OpenSSH public key, then press Enter."
	case "user_totp_setup":
		secret, err := totp.GenerateSecret()
		if err != nil {
			m.closeModal("TOTP setup failed: " + err.Error())
			return nil
		}
		uri := totp.URI("SSHGateW", p.username, secret)
		qr, err := totp.QR(uri)
		if err != nil {
			m.closeModal("TOTP QR generation failed: " + err.Error())
			return nil
		}
		p.kind, p.totpSecret, p.totpURI, p.totpQR = "user_totp_setup", secret, uri, qr
		m.mode = "totp_enroll"
		m.status = "Scan the QR code, then press Enter."
	case "user_key_remove":
		keys, err := m.store.ListGatewayKeys(m.ctx, p.username)
		if err != nil || len(keys) == 0 {
			m.closeModal("No SSH keys available to remove.")
			return nil
		}
		m.actions = make([]actionItem, 0, len(keys))
		for _, key := range keys {
			label := key.Fingerprint
			if key.Label != "" {
				label += "  " + key.Label
			}
			m.actions = append(m.actions, actionItem{label: label, code: key.Fingerprint})
		}
		m.mode, m.actionCursor = "key_remove", 0
	case "user_role":
		role := store.RoleAdmin
		if p.user.Role == store.RoleAdmin {
			role = store.RoleMember
		}
		return m.mutate("users", "User role updated.", "admin.user.role", map[string]any{"username": p.username, "role": role}, func() error { return m.store.SetUserRole(m.ctx, p.username, role) })
	case "user_toggle":
		enabled := !p.user.Enabled
		return m.mutate("users", "User updated.", "admin.user."+enabledWord(enabled), map[string]any{"username": p.username}, func() error { return m.store.SetUserEnabled(m.ctx, p.username, enabled) })
	case "group_member_add", "group_member_remove":
		adding := code == "group_member_add"
		m.actions = nil
		for _, u := range m.users {
			member := m.isGroupMember(p.group, u.Username)
			if member != adding {
				m.actions = append(m.actions, actionItem{label: u.Username, code: u.Username})
			}
		}
		if len(m.actions) == 0 {
			m.closeModal("No eligible users for that membership action.")
			return nil
		}
		m.mode, m.actionCursor = strings.TrimPrefix(code, "group_"), 0
	case "key_remove":
		fingerprint := m.actions[m.actionCursor].code
		return m.mutate("users", "SSH key removed.", "admin.gateway_key.remove", map[string]any{"username": p.username, "fingerprint": fingerprint}, func() error { return m.store.RemoveGatewayKey(m.ctx, p.username, fingerprint) })
	case "member_add", "member_remove":
		username := m.actions[m.actionCursor].code
		adding := code == "member_add"
		return m.mutate("groups", "Membership updated.", "admin.group.member."+addRemove(adding), map[string]any{"group": p.group, "username": username}, func() error { return m.store.SetGroupMember(m.ctx, p.group, username, adding) })
	}
	return nil
}

func (m *Model) handleFormKey(key string) tea.Cmd {
	if key == "esc" {
		m.closeModal("Cancelled.")
		return nil
	}
	f := m.form
	if f == nil || len(f.fields) == 0 {
		return nil
	}
	field := &f.fields[f.index]
	switch key {
	case "up", "shift+tab":
		if f.index > 0 {
			f.index--
		}
	case "down", "tab":
		if f.index < len(f.fields)-1 {
			f.index++
		}
	case "left", "right", "space":
		if len(field.options) > 0 {
			delta := 1
			if key == "left" {
				delta = -1
			}
			cycleOption(field, delta)
			m.syncFormOptions()
		} else if key == "space" {
			field.value += " "
		}
	case "backspace":
		if len(field.options) == 0 {
			field.value = removeLastRune(field.value)
		}
	case "ctrl+u":
		if len(field.options) == 0 {
			field.value = ""
		}
	case "enter":
		if f.index < len(f.fields)-1 {
			f.index++
		} else {
			return m.submitForm()
		}
	default:
		if len(field.options) == 0 && len([]rune(key)) == 1 {
			field.value += key
		}
	}
	return nil
}

func (m *Model) syncFormOptions() {
	if m.form == nil {
		return
	}
	if m.form.kind == "target_add" || m.form.kind == "target_credential" {
		m.syncTargetKeyField()
		return
	}
	if m.form.kind != "grant_add" || len(m.form.fields) < 3 {
		return
	}
	principal := &m.form.fields[2]
	if m.form.fields[1].value == "group" {
		principal.options = groupNames(m.groups)
	} else {
		principal.options = userNames(m.users)
	}
	if len(principal.options) > 0 && !contains(principal.options, principal.value) {
		principal.value = principal.options[0]
	}
}

func (m *Model) syncTargetKeyField() {
	if m.form == nil {
		return
	}
	authIndex := 0
	baseFields := 1
	if m.form.kind == "target_add" {
		authIndex = 4
		baseFields = 5
	} else if m.form.kind != "target_credential" {
		return
	}
	if len(m.form.fields) < baseFields {
		return
	}
	storedKey := m.form.fields[authIndex].value == store.CredentialStoredKey
	if storedKey && len(m.form.fields) == baseFields {
		m.form.fields = append(m.form.fields, formField{label: "Saved SSH key", value: selectedIdentityName(m.identities, m.pendingIdentityID()), options: identityNames(m.identities)})
	} else if !storedKey && len(m.form.fields) > baseFields {
		m.form.fields = m.form.fields[:baseFields]
		if m.form.index >= baseFields {
			m.form.index = baseFields - 1
		}
	}
}

func (m *Model) pendingIdentityID() *int64 {
	if m.pending == nil || m.form == nil || m.form.kind != "target_credential" {
		return nil
	}
	return m.pending.target.IdentityID
}

func (m *Model) submitForm() tea.Cmd {
	f := m.form
	values := make([]string, len(f.fields))
	authentication := ""
	for _, field := range f.fields {
		if field.label == "Authentication" {
			authentication = strings.TrimSpace(field.value)
			break
		}
	}
	for i := range f.fields {
		values[i] = strings.TrimSpace(f.fields[i].value)
		if f.fields[i].label == "Saved SSH key" && authentication != store.CredentialStoredKey {
			continue
		}
		if values[i] == "" {
			m.status = f.fields[i].label + " is required."
			f.index = i
			return nil
		}
	}
	switch f.kind {
	case "identity_add":
		m.pending = &pendingOperation{kind: "identity_add", name: values[0]}
		m.form = nil
		if values[1] == "generate_ed25519" {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				m.closeModal("Key generation failed: " + err.Error())
				return nil
			}
			block, err := gossh.MarshalPrivateKey(privateKey, "SSHGateW generated key: "+values[0])
			if err != nil {
				m.closeModal("Key generation failed: " + err.Error())
				return nil
			}
			return m.finishIdentity(pem.EncodeToMemory(block))
		}
		m.mode, m.input = "secret_key", ""
		m.status = "Paste the private key, then press Ctrl+D."
		return nil
	case "user_add":
		return m.mutate("users", "User added.", "admin.user.add", map[string]any{"username": values[0], "role": values[1]}, func() error { _, err := m.store.AddUser(m.ctx, values[0], values[1]); return err })
	case "group_add":
		return m.mutate("groups", "Group added.", "admin.group.add", map[string]any{"group": values[0]}, func() error { return m.store.AddGroup(m.ctx, values[0]) })
	case "grant_add":
		return m.mutate("grants", "Access granted.", "admin.grant.add", map[string]any{"target": values[0], "kind": values[1], "principal": values[2]}, func() error {
			return m.store.SetGrantCapabilities(m.ctx, values[0], values[1], values[2], true, values[3] == "yes", values[4] == "yes", values[5] == "yes", values[6] == "yes")
		})
	case "grant_edit":
		g := m.pending.grant
		return m.mutate("grants", "Grant capabilities updated.", "admin.grant.edit", map[string]any{"target": g.Target, "kind": g.Kind, "principal": g.Principal}, func() error {
			return m.store.SetGrantCapabilities(m.ctx, g.Target, g.Kind, g.Principal, true, values[0] == "yes", values[1] == "yes", values[2] == "yes", values[3] == "yes")
		})
	case "forward_add":
		port, err := strconv.Atoi(values[2])
		if err != nil || port < 1 || port > 65535 {
			m.status, f.index = "Port must be between 1 and 65535.", 2
			return nil
		}
		return m.mutate("forwards", "TCP destination allowed.", "admin.forward.add", map[string]any{"target": values[0], "host": values[1], "port": port}, func() error { return m.store.AddForwardRule(m.ctx, values[0], values[1], port) })
	case "target_edit":
		port, err := strconv.Atoi(values[1])
		if err != nil || port < 1 || port > 65535 {
			m.status, f.index = "Port must be between 1 and 65535.", 1
			return nil
		}
		p := m.pending
		return m.mutate("targets", "Target updated.", "admin.target.edit", map[string]any{"target": p.target.Name}, func() error { return m.store.UpdateTarget(m.ctx, p.target.Name, values[0], port, values[2]) })
	case "target_credential":
		m.pending.kind, m.pending.credentialKind = "credential", values[0]
		m.form = nil
		if values[0] == store.CredentialStoredKey {
			identity, err := m.store.SSHIdentityByName(m.ctx, values[1])
			if err != nil {
				m.closeModal("Saved SSH key unavailable: " + err.Error())
				return nil
			}
			p := m.pending
			return m.mutate("targets", "Credential replaced with saved SSH key.", "admin.target.credential.replace", map[string]any{"target": p.target.Name, "credential_kind": values[0], "ssh_key": identity.Name, "fingerprint": identity.Fingerprint}, func() error { return m.store.SetTargetIdentity(m.ctx, p.target.ID, identity.ID) })
		} else if values[0] == store.CredentialPassword {
			m.mode, m.input = "secret_password", ""
			m.status = "Enter the downstream password, then press Enter."
		} else if values[0] == store.CredentialPrivateKey {
			m.mode, m.input = "secret_key", ""
			m.status = "Paste the private key, then press Ctrl+D."
		} else {
			m.mode, m.input = "agent_key", ""
			m.status = "Paste the public key that the forwarded agent must provide."
		}
		return nil
	case "target_add":
		port, err := strconv.Atoi(values[2])
		if err != nil || port < 1 || port > 65535 {
			m.status, f.index = "Port must be between 1 and 65535.", 2
			return nil
		}
		m.pending = &pendingOperation{kind: "target_add", name: values[0], host: values[1], port: port, remote: values[3], credentialKind: values[4]}
		if values[4] == store.CredentialStoredKey {
			if values[5] == "" {
				m.status, f.index = "Create an SSH key first, then select it here.", 5
				return nil
			}
			identity, err := m.store.SSHIdentityByName(m.ctx, values[5])
			if err != nil {
				m.status, f.index = "Saved SSH key unavailable: "+err.Error(), 5
				return nil
			}
			m.pending.identity, m.pending.identityID = identity, identity.ID
		}
		m.form = nil
		return m.scanHost(net.JoinHostPort(values[1], values[2]))
	}
	return nil
}

func (m *Model) finishPublicKey() tea.Cmd {
	p := m.pending
	raw := strings.TrimSpace(m.input)
	key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		m.status = "Invalid public key: " + err.Error()
		return nil
	}
	canonical := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key)))
	fingerprint := gossh.FingerprintSHA256(key)
	return m.mutate("users", "SSH key added.", "admin.gateway_key.add", map[string]any{"username": p.username, "fingerprint": fingerprint}, func() error { return m.store.AddGatewayKey(m.ctx, p.username, fingerprint, canonical, "") })
}

func (m *Model) finishAgentKey() tea.Cmd {
	raw := strings.TrimSpace(m.input)
	key, _, _, rest, err := gossh.ParseAuthorizedKey([]byte(raw))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		if err == nil {
			err = errors.New("paste exactly one public key")
		}
		m.status = "Invalid forwarded-agent public key: " + err.Error()
		return nil
	}
	canonical := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key)))
	m.status = "Forwarded-agent key " + gossh.FingerprintSHA256(key) + " accepted."
	return m.finishCredential(secrets.Payload{PublicKey: []byte(canonical)})
}

func (m *Model) finishDelete() tea.Cmd {
	p := m.pending
	switch p.kind {
	case "target_delete":
		return m.mutate("targets", "Target deleted.", "admin.target.delete", map[string]any{"target": p.target.Name}, func() error { return m.store.DeleteTarget(m.ctx, p.target.Name) })
	case "user_delete":
		return m.mutate("users", "User deleted.", "admin.user.delete", map[string]any{"username": p.username}, func() error { return m.store.DeleteUser(m.ctx, p.username) })
	case "group_delete":
		return m.mutate("groups", "Group deleted.", "admin.group.delete", map[string]any{"group": p.group}, func() error { return m.store.DeleteGroup(m.ctx, p.group) })
	case "grant_delete":
		g := p.grant
		return m.mutate("grants", "Access removed.", "admin.grant.remove", map[string]any{"target": g.Target, "kind": g.Kind, "principal": g.Principal}, func() error { return m.store.SetGrant(m.ctx, g.Target, g.Kind, g.Principal, false) })
	case "forward_delete":
		r := p.forwardRule
		return m.mutate("forwards", "TCP destination removed.", "admin.forward.remove", map[string]any{"target": r.Target, "host": r.Host, "port": r.Port}, func() error { return m.store.DeleteForwardRule(m.ctx, r.ID) })
	case "user_totp_remove":
		return m.mutate("users", "TOTP removed.", "admin.user.totp.remove", map[string]any{"username": p.username}, func() error { return m.store.RemoveUserTOTP(m.ctx, p.user.ID) })
	case "identity_delete":
		return m.mutate("keys", "SSH key deleted.", "admin.ssh_identity.delete", map[string]any{"ssh_key": p.identity.Name, "fingerprint": p.identity.Fingerprint}, func() error { return m.store.DeleteSSHIdentity(m.ctx, p.identity.Name) })
	}
	return nil
}

func (m *Model) finishTOTPEnrollment() tea.Cmd {
	p := m.pending
	counter, valid := totp.Validate(p.totpSecret, m.input, time.Now())
	if !valid {
		m.status, m.input = "Invalid TOTP code. Try a fresh code.", ""
		return nil
	}
	return m.mutate("users", "TOTP enabled.", "admin.user.totp.enable", map[string]any{"username": p.username}, func() error {
		nonce, ciphertext, err := m.cipher.EncryptTOTP(p.user.ID, p.totpSecret)
		if err == nil {
			err = m.store.SetUserTOTP(m.ctx, p.user.ID, nonce, ciphertext)
		}
		if err == nil {
			err = m.store.ConsumeTOTPCounter(m.ctx, p.user.ID, counter)
		}
		return err
	})
}

func (m *Model) verifyTOTPChallenge() {
	config, err := m.store.UserTOTP(m.ctx, m.user.ID)
	if err == nil {
		var secret string
		secret, err = m.cipher.DecryptTOTP(m.user.ID, config.Nonce, config.Ciphertext)
		if err == nil {
			counter, valid := totp.Validate(secret, m.input, time.Now())
			if !valid {
				err = errors.New("invalid verification code")
			} else {
				err = m.store.ConsumeTOTPCounter(m.ctx, m.user.ID, counter)
			}
		}
	}
	m.input = ""
	if err != nil {
		m.totpAttempts++
		if m.totpAttempts >= 5 {
			m.result = &Result{Quit: true}
			return
		}
		m.status = "Verification failed. Enter a fresh code."
		return
	}
	m.result = &Result{Verified: true}
}

func (m *Model) mutate(section, status, event string, details map[string]any, fn func() error) tea.Cmd {
	return func() tea.Msg {
		err := fn()
		if err == nil {
			err = m.audit(event, details)
		}
		return mutationMsg{status: status, section: section, err: err}
	}
}

func (m *Model) isGroupMember(group, username string) bool {
	for _, member := range m.groupMembers {
		if member.Group == group && member.Username == username {
			return true
		}
	}
	return false
}

func targetNames(values []store.Target) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = values[i].Name
	}
	return out
}
func userNames(values []store.User) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = values[i].Username
	}
	return out
}
func groupNames(values []store.Group) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = values[i].Name
	}
	return out
}
func identityNames(values []store.SSHIdentity) []string {
	out := make([]string, len(values))
	for i := range values {
		out[i] = values[i].Name
	}
	return out
}
func firstIdentity(values []store.SSHIdentity) string {
	if len(values) == 0 {
		return ""
	}
	return values[0].Name
}
func selectedIdentityName(values []store.SSHIdentity, selected *int64) string {
	if selected != nil {
		for _, identity := range values {
			if identity.ID == *selected {
				return identity.Name
			}
		}
	}
	return firstIdentity(values)
}
func credentialKinds() []string {
	return []string{store.CredentialPrivateKey, store.CredentialPassword, store.CredentialStoredKey, store.CredentialAgent}
}
func firstUser(values []store.User) string {
	if len(values) == 0 {
		return ""
	}
	return values[0].Username
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func enabledWord(enabled bool) string {
	if enabled {
		return "enable"
	}
	return "disable"
}
func addRemove(add bool) string {
	if add {
		return "add"
	}
	return "remove"
}
func cycleOption(field *formField, delta int) {
	if len(field.options) == 0 {
		return
	}
	index := 0
	for i, option := range field.options {
		if option == field.value {
			index = i
			break
		}
	}
	index = (index + delta + len(field.options)) % len(field.options)
	field.value = field.options[index]
}

func (m *Model) runCommand(line string) tea.Cmd {
	f := strings.Fields(line)
	if len(f) == 0 {
		return nil
	}
	if f[0] == "help" {
		m.mode = "help"
		return nil
	}
	mutate := func(fn func() error, ok string) tea.Cmd {
		return func() tea.Msg { e := fn(); return mutationMsg{status: ok, err: e} }
	}
	switch f[0] {
	case "user":
		if len(f) >= 3 {
			switch f[1] {
			case "add":
				role := store.RoleMember
				if len(f) > 3 {
					role = f[3]
				}
				return mutate(func() error {
					_, e := m.store.AddUser(m.ctx, f[2], role)
					if e == nil {
						e = m.audit("admin.user.add", map[string]any{"username": f[2], "role": role})
					}
					return e
				}, "User added.")
			case "delete":
				return mutate(func() error {
					e := m.store.DeleteUser(m.ctx, f[2])
					if e == nil {
						e = m.audit("admin.user.delete", map[string]any{"username": f[2]})
					}
					return e
				}, "User deleted.")
			case "enable", "disable":
				enabled := f[1] == "enable"
				return mutate(func() error {
					e := m.store.SetUserEnabled(m.ctx, f[2], enabled)
					if e == nil {
						e = m.audit("admin.user."+f[1], map[string]any{"username": f[2]})
					}
					return e
				}, "User updated.")
			case "role":
				if len(f) == 4 {
					return mutate(func() error {
						e := m.store.SetUserRole(m.ctx, f[2], f[3])
						if e == nil {
							e = m.audit("admin.user.role", map[string]any{"username": f[2], "role": f[3]})
						}
						return e
					}, "Role updated.")
				}
			}
		}
	case "key":
		if len(f) >= 4 && f[1] == "remove" {
			return mutate(func() error {
				e := m.store.RemoveGatewayKey(m.ctx, f[2], f[3])
				if e == nil {
					e = m.audit("admin.gateway_key.remove", map[string]any{"username": f[2], "fingerprint": f[3]})
				}
				return e
			}, "Gateway key removed.")
		}
		if len(f) >= 5 && f[1] == "add" {
			raw := strings.Join(f[3:], " ")
			k, _, _, _, e := gossh.ParseAuthorizedKey([]byte(raw))
			if e != nil {
				m.status = "Invalid public key: " + e.Error()
				return nil
			}
			canonical := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(k)))
			fp := gossh.FingerprintSHA256(k)
			return mutate(func() error {
				e := m.store.AddGatewayKey(m.ctx, f[2], fp, canonical, "")
				if e == nil {
					e = m.audit("admin.gateway_key.add", map[string]any{"username": f[2], "fingerprint": fp})
				}
				return e
			}, "Gateway key added.")
		}
	case "group":
		if len(f) == 3 && (f[1] == "add" || f[1] == "delete") {
			return mutate(func() error {
				var e error
				if f[1] == "add" {
					e = m.store.AddGroup(m.ctx, f[2])
				} else {
					e = m.store.DeleteGroup(m.ctx, f[2])
				}
				if e == nil {
					e = m.audit("admin.group."+f[1], map[string]any{"group": f[2]})
				}
				return e
			}, "Group updated.")
		}
	case "member":
		if len(f) == 4 && (f[1] == "add" || f[1] == "remove") {
			return mutate(func() error {
				e := m.store.SetGroupMember(m.ctx, f[2], f[3], f[1] == "add")
				if e == nil {
					e = m.audit("admin.group.member."+f[1], map[string]any{"group": f[2], "username": f[3]})
				}
				return e
			}, "Membership updated.")
		}
	case "grant":
		if len(f) == 5 && (f[1] == "add" || f[1] == "remove") {
			return mutate(func() error {
				e := m.store.SetGrant(m.ctx, f[2], f[3], f[4], f[1] == "add")
				if e == nil {
					e = m.audit("admin.grant."+f[1], map[string]any{"target": f[2], "kind": f[3], "principal": f[4]})
				}
				return e
			}, "Grant updated.")
		}
	case "target":
		if len(f) >= 3 {
			switch f[1] {
			case "delete":
				return mutate(func() error {
					e := m.store.DeleteTarget(m.ctx, f[2])
					if e == nil {
						e = m.audit("admin.target.delete", map[string]any{"target": f[2]})
					}
					return e
				}, "Target deleted.")
			case "enable", "disable":
				enabled := f[1] == "enable"
				return mutate(func() error {
					e := m.store.SetTargetEnabled(m.ctx, f[2], enabled)
					if e == nil {
						e = m.audit("admin.target."+f[1], map[string]any{"target": f[2]})
					}
					return e
				}, "Target updated.")
			case "edit":
				if len(f) == 6 {
					port, e := strconv.Atoi(f[4])
					if e != nil {
						m.status = "Port must be numeric."
						return nil
					}
					return mutate(func() error {
						e := m.store.UpdateTarget(m.ctx, f[2], f[3], port, f[5])
						if e == nil {
							e = m.audit("admin.target.edit", map[string]any{"target": f[2]})
						}
						return e
					}, "Target updated.")
				}
			case "add":
				if len(f) == 7 {
					port, e := strconv.Atoi(f[4])
					if e != nil {
						m.status = "Port must be numeric."
						return nil
					}
					if f[6] != store.CredentialPassword && f[6] != store.CredentialPrivateKey {
						m.status = "Credential kind must be password or private_key."
						return nil
					}
					m.pending = &pendingOperation{kind: "target_add", name: f[2], host: f[3], port: port, remote: f[5], credentialKind: f[6]}
					return m.scanHost(net.JoinHostPort(f[3], f[4]))
				}
			}
		}
	case "credential":
		if len(f) == 4 && f[1] == "replace" {
			t, e := m.store.TargetByName(m.ctx, f[2])
			if e != nil {
				m.status = e.Error()
				return nil
			}
			if f[3] != store.CredentialPassword && f[3] != store.CredentialPrivateKey {
				m.status = "Credential kind must be password or private_key."
				return nil
			}
			m.pending = &pendingOperation{kind: "credential", target: t, credentialKind: f[3]}
			if f[3] == store.CredentialPassword {
				m.mode = "secret_password"
				m.status = "Enter replacement password (hidden), then press Enter."
			} else {
				m.mode = "secret_key"
				m.status = "Paste replacement private key, then press Ctrl+D."
			}
			return nil
		}
	case "host-key":
		if len(f) == 3 && f[1] == "replace" {
			t, e := m.store.TargetByName(m.ctx, f[2])
			if e != nil {
				m.status = e.Error()
				return nil
			}
			m.pending = &pendingOperation{kind: "host_key", target: t}
			return m.scanHost(net.JoinHostPort(t.Host, strconv.Itoa(t.Port)))
		}
	}
	m.status = "Invalid admin command. Type : then 'help' for syntax."
	return nil
}

func (m *Model) scanHost(address string) tea.Cmd {
	m.mode = "scanning"
	m.status = "Scanning downstream host key…"
	return func() tea.Msg {
		k, e := downstream.ScanHostKey(m.ctx, address, m.timeout)
		return hostKeyMsg{key: k, err: e}
	}
}
func (m *Model) finishHostKey() tea.Cmd {
	p := m.pending
	return func() tea.Msg {
		canonical := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(p.hostKey)))
		e := m.store.SetTargetHostKey(m.ctx, p.target.Name, p.hostKey.Type(), canonical)
		if e == nil {
			e = m.audit("admin.target.host_key.replace", map[string]any{"target": p.target.Name, "fingerprint": gossh.FingerprintSHA256(p.hostKey)})
		}
		return mutationMsg{status: "Host key replaced.", err: e}
	}
}
func (m *Model) finishIdentity(privateKey []byte) tea.Cmd {
	return m.finishIdentityPayload(privateKey, "")
}
func (m *Model) finishIdentityWithPassphrase(privateKey []byte, passphrase string) tea.Cmd {
	return m.finishIdentityPayload(privateKey, passphrase)
}
func (m *Model) finishIdentityPayload(privateKey []byte, passphrase string) tea.Cmd {
	p := m.pending
	var signer gossh.Signer
	var err error
	if passphrase == "" {
		signer, err = gossh.ParsePrivateKey(privateKey)
	} else {
		signer, err = gossh.ParsePrivateKeyWithPassphrase(privateKey, []byte(passphrase))
	}
	if err != nil {
		m.status = "Invalid private key: " + err.Error()
		return nil
	}
	publicKey := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	fingerprint := gossh.FingerprintSHA256(signer.PublicKey())
	payload := secrets.Payload{PrivateKey: privateKey, Passphrase: passphrase}
	m.input = ""
	m.mode = "saving"
	return func() tea.Msg {
		if m.cipher == nil {
			return mutationMsg{err: errors.New("credential cipher unavailable")}
		}
		identity, e := m.store.AddSSHIdentity(m.ctx, p.name, publicKey, fingerprint)
		if e != nil {
			return mutationMsg{err: e}
		}
		nonce, ciphertext, e := m.cipher.EncryptSSHIdentity(identity.ID, payload)
		if e == nil {
			e = m.store.SetSSHIdentitySecret(m.ctx, identity.ID, nonce, ciphertext)
		}
		if e != nil {
			_ = m.store.DeleteSSHIdentity(m.ctx, identity.Name)
			return mutationMsg{err: e}
		}
		e = m.audit("admin.ssh_identity.add", map[string]any{"ssh_key": identity.Name, "fingerprint": fingerprint})
		return mutationMsg{status: "SSH key stored.", section: "keys", err: e}
	}
}
func (m *Model) finishStoredTarget() tea.Cmd {
	p := m.pending
	return func() tea.Msg {
		identityID := p.identityID
		t, err := m.store.AddTarget(m.ctx, store.NewTarget{Name: p.name, Host: p.host, Port: p.port, RemoteUsername: p.remote, CredentialKind: store.CredentialStoredKey, IdentityID: &identityID, HostKeyAlgorithm: p.hostKey.Type(), HostPublicKey: strings.TrimSpace(string(gossh.MarshalAuthorizedKey(p.hostKey)))})
		if err == nil {
			err = m.audit("admin.target.add", map[string]any{"target": t.Name, "credential_kind": store.CredentialStoredKey, "ssh_key": p.identity.Name, "fingerprint": p.identity.Fingerprint, "host_key": gossh.FingerprintSHA256(p.hostKey)})
		}
		return mutationMsg{status: "Target added with saved SSH key.", section: "targets", err: err}
	}
}
func (m *Model) finishCredential(payload secrets.Payload) tea.Cmd {
	p := m.pending
	input := m.input
	m.input = ""
	_ = input
	return func() tea.Msg {
		if m.cipher == nil {
			return mutationMsg{err: errors.New("credential cipher unavailable")}
		}
		if p.kind == "target_add" {
			t, e := m.store.AddTarget(m.ctx, store.NewTarget{Name: p.name, Host: p.host, Port: p.port, RemoteUsername: p.remote, CredentialKind: p.credentialKind, HostKeyAlgorithm: p.hostKey.Type(), HostPublicKey: strings.TrimSpace(string(gossh.MarshalAuthorizedKey(p.hostKey)))})
			if e != nil {
				return mutationMsg{err: e}
			}
			nonce, ct, e := m.cipher.Encrypt(t.ID, p.credentialKind, payload)
			if e == nil {
				e = m.store.SetTargetCredential(m.ctx, t.ID, nonce, ct)
			}
			if e != nil {
				_ = m.store.DeleteTarget(m.ctx, t.Name)
				return mutationMsg{err: e}
			}
			e = m.audit("admin.target.add", map[string]any{"target": t.Name, "credential_kind": p.credentialKind, "host_key": gossh.FingerprintSHA256(p.hostKey)})
			return mutationMsg{status: "Target added and credential saved.", section: "targets", err: e}
		}
		nonce, ct, e := m.cipher.Encrypt(p.target.ID, p.credentialKind, payload)
		if e == nil {
			e = m.store.SetTargetCredentialKind(m.ctx, p.target.ID, p.credentialKind, nonce, ct)
		}
		if e == nil {
			e = m.audit("admin.target.credential.replace", map[string]any{"target": p.target.Name, "credential_kind": p.credentialKind})
		}
		return mutationMsg{status: "Credential replaced.", section: "targets", err: e}
	}
}
func (m *Model) audit(event string, details map[string]any) error {
	b, _ := json.Marshal(details)
	return m.store.Audit(m.ctx, store.AuditEvent{ActorUserID: &m.user.ID, ClaimedUsername: m.user.Username, SourceAddress: m.sourceAddress, EventType: event, Outcome: "success", Details: string(b)})
}

func (m *Model) filtered() []store.Target {
	if m.query == "" {
		return m.targets
	}
	var out []store.Target
	q := strings.ToLower(m.query)
	for _, t := range m.targets {
		if strings.Contains(strings.ToLower(t.Name+" "+t.Host+" "+t.RemoteUsername), q) {
			out = append(out, t)
		}
	}
	return out
}
func (m *Model) itemCount() int {
	switch m.section {
	case "keys":
		return len(m.identities)
	case "users":
		return len(m.users)
	case "groups":
		return len(m.groups)
	case "grants":
		return len(m.grants)
	case "forwards":
		return len(m.forwardRules)
	case "audit":
		return len(m.auditEvents)
	default:
		return len(m.filtered())
	}
}
func (m *Model) clamp() {
	n := m.itemCount()
	if n == 0 {
		m.cursor = 0
	} else if m.cursor >= n {
		m.cursor = n - 1
	}
}
func (m *Model) pageSize() int {
	h := m.height
	if h <= 0 {
		h = 24
	}
	if h > 1 {
		h--
	}
	if h < 10 {
		return 1
	}
	return h - 8
}
func (m *Model) changeSection(delta int) {
	sections := []string{"targets", "keys", "users", "groups", "grants", "forwards", "audit"}
	current := 0
	for i, section := range sections {
		if section == m.section {
			current = i
			break
		}
	}
	current = (current + delta + len(sections)) % len(sections)
	m.section, m.cursor, m.query, m.searching = sections[current], 0, "", false
}

const (
	reset      = "\x1b[0m"
	bold       = "\x1b[1m"
	dim        = "\x1b[2m"
	cyan       = "\x1b[36m"
	brightCyan = "\x1b[1;96m"
	green      = "\x1b[32m"
	red        = "\x1b[31m"
	yellow     = "\x1b[33m"
)

func (m *Model) View() tea.View {
	w, h := m.width, m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	// Reserve a one-cell gutter. Writing into the final terminal column can
	// trigger automatic wrapping on remote PTYs, making a full-frame view one
	// row taller than Bubble Tea expects and leaving only a cleared screen.
	if w > 1 {
		w--
	}
	if h > 1 {
		h--
	}
	if w < 20 || h < 8 {
		return m.compactView(w, h)
	}
	if m.mode == "totp_enroll" {
		return m.totpEnrollmentView(w, h)
	}
	inner := w - 4
	lines := make([]string, 0, h)
	role := strings.ToUpper(m.user.Role)
	lines = append(lines, joinSides(brightCyan+" SSHGateW "+reset, dim+m.user.Username+" • "+role+reset, w))
	lines = append(lines, m.tabLine(w))
	lines = append(lines, dim+strings.Repeat("─", w)+reset)

	title, contextLine, rows := m.content(inner)
	lines = append(lines, fit(contextLine, w))
	listHeight := h - 8
	if listHeight < 1 {
		listHeight = 1
	}
	hasSelectableRows := len(rows) > 0
	start, end := visibleRange(m.cursor, len(rows), listHeight)
	label := title
	if len(rows) > 0 && m.mode == "" {
		label = fmt.Sprintf("%s  %d–%d of %d", title, start+1, end, len(rows))
	}
	lines = append(lines, borderTop(label, w))
	if len(rows) == 0 {
		rows = []string{dim + "Nothing to show here yet." + reset}
		start, end = 0, 1
	}
	for i := start; i < end; i++ {
		row := fit(rows[i], inner)
		if m.mode == "" && hasSelectableRows && i == m.cursor {
			row = brightCyan + row + reset
		}
		lines = append(lines, dim+"│"+reset+" "+row+" "+dim+"│"+reset)
	}
	for len(lines) < h-3 {
		lines = append(lines, dim+"│"+reset+strings.Repeat(" ", w-2)+dim+"│"+reset)
	}
	lines = append(lines, borderBottom(w))
	lines = append(lines, m.statusLine(w))
	lines = append(lines, fit(m.footer(), w))
	if len(lines) > h {
		lines = lines[:h]
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	v.WindowTitle = "SSHGateW"
	return v
}

func (m *Model) totpEnrollmentView(w, h int) tea.View {
	lines := []string{fit(brightCyan+" SSHGateW • TOTP enrollment "+reset, w)}
	if m.pending != nil {
		for _, qrLine := range m.pending.totpQR {
			padding := maxInt((w-ansi.StringWidth(qrLine))/2, 0)
			coloredQR := "\x1b[47;30m" + qrLine + reset
			lines = append(lines, fit(strings.Repeat(" ", padding)+coloredQR, w))
		}
	}
	for len(lines) < h-1 {
		lines = append(lines, strings.Repeat(" ", w))
	}
	lines = append(lines, fit(dim+"  Scan QR  •  Enter continue  •  Esc cancel"+reset, w))
	if len(lines) > h {
		lines = lines[:h]
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	v.WindowTitle = "SSHGateW TOTP enrollment"
	return v
}

func (m *Model) compactView(w, h int) tea.View {
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	lines := []string{fit(brightCyan+"SSHGateW"+reset, w), fit(m.user.Username+" • "+strings.ToUpper(m.user.Role), w), fit("Terminal too small", w), fit("Resize to at least 20×8", w)}
	if len(lines) > h {
		lines = lines[:h]
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	v.WindowTitle = "SSHGateW"
	return v
}

func (m *Model) tabLine(w int) string {
	if m.user.Role != store.RoleAdmin {
		return fit("  CONNECTION PROFILES", w)
	}
	sections := []struct{ key, name string }{{"1", "targets"}, {"2", "keys"}, {"3", "users"}, {"4", "groups"}, {"5", "grants"}, {"6", "forwards"}, {"7", "audit"}}
	parts := make([]string, 0, len(sections))
	for _, s := range sections {
		name := strings.ToUpper(s.name)
		if m.section == s.name {
			parts = append(parts, brightCyan+"["+s.key+"] "+name+reset)
		} else {
			parts = append(parts, dim+"["+s.key+"] "+name+reset)
		}
	}
	return fit(" "+strings.Join(parts, "  "), w)
}

func (m *Model) content(inner int) (string, string, []string) {
	if m.mode != "" {
		return m.modalContent(inner)
	}
	var rows []string
	switch m.section {
	case "keys":
		for _, identity := range m.identities {
			algorithm := strings.Fields(identity.PublicKey)
			keyType := "SSH"
			if len(algorithm) > 0 {
				keyType = strings.TrimPrefix(strings.ToUpper(algorithm[0]), "SSH-")
			}
			uses := 0
			for _, target := range m.targets {
				if target.IdentityID != nil && *target.IdentityID == identity.ID {
					uses++
				}
			}
			rows = append(rows, fmt.Sprintf("  %-20s  %-11s  %d target(s)  %s", identity.Name, keyType, uses, identity.Fingerprint))
		}
		return "SSH keys", dim + "  Encrypted reusable downstream identities" + reset, rows
	case "users":
		for _, u := range m.users {
			state := "ENABLED"
			if !u.Enabled {
				state = "DISABLED"
			}
			mfa := "TOTP OFF"
			if u.TOTPEnabled {
				mfa = "TOTP ON"
			}
			rows = append(rows, fmt.Sprintf("  %-20s  %-8s  %-8s  %s", u.Username, strings.ToUpper(u.Role), mfa, state))
		}
		return "Users", dim + "  Gateway identities and roles" + reset, rows
	case "groups":
		for _, g := range m.groups {
			count := 0
			for _, member := range m.groupMembers {
				if member.Group == g.Name {
					count++
				}
			}
			rows = append(rows, fmt.Sprintf("  %-28s  %d member(s)", g.Name, count))
		}
		return "Groups", dim + "  Access-control groups" + reset, rows
	case "grants":
		for _, g := range m.grants {
			caps := []string{}
			if g.Shell {
				caps = append(caps, "shell")
			}
			if g.SFTP {
				caps = append(caps, "sftp")
			}
			if g.SCP {
				caps = append(caps, "scp")
			}
			if g.TCPForward {
				caps = append(caps, "tcp")
			}
			rows = append(rows, fmt.Sprintf("  %-18s  %-7s  %-16s  %s", g.Target, strings.ToUpper(g.Kind), g.Principal, strings.Join(caps, ",")))
		}
		return "Grants", dim + "  Target → principal protocol capabilities" + reset, rows
	case "forwards":
		for _, r := range m.forwardRules {
			rows = append(rows, fmt.Sprintf("  %-22s  %s:%d", r.Target, r.Host, r.Port))
		}
		return "TCP forwarding", dim + "  Exact destinations reachable through selected targets" + reset, rows
	case "audit":
		for _, e := range m.auditEvents {
			actor := e.ClaimedUsername
			if actor == "" {
				actor = "system"
			}
			rows = append(rows, fmt.Sprintf("  %s  %-25s  %-7s  %s", e.At.Local().Format("01-02 15:04:05"), e.EventType, strings.ToUpper(e.Outcome), actor))
		}
		return "Recent audit events", dim + "  Newest first • metadata only" + reset, rows
	default:
		for _, t := range m.filtered() {
			state := ""
			if !t.Enabled {
				state = red + "  DISABLED" + reset
			}
			rows = append(rows, fmt.Sprintf("  %-20s  %-15s  %s@%s:%d%s", t.Name, t.CredentialKind, t.RemoteUsername, t.Host, t.Port, state))
		}
		prompt := "  / Search profiles"
		if m.searching {
			prompt = yellow + "  Search: " + reset + m.query + "▏"
		} else if m.query != "" {
			prompt = "  Filter: " + m.query + dim + "  • Esc clears" + reset
		}
		return "Connection profiles", prompt, rows
	}
}

func (m *Model) modalContent(inner int) (string, string, []string) {
	switch m.mode {
	case "help":
		return "Keyboard help", "  Press any key to return", []string{"  ↑/↓ or j/k     Move selection", "  Enter          Connect/manage selected item", "  a              Add item in current section", "  m              Manage selected item", "  Tab            Move through form fields", "  ←/→            Change option or section", "  /              Search targets", "  1–6            Change admin section", "  r              Refresh data", "  q              Disconnect from SSHGateW"}
	case "form":
		if m.form == nil {
			return "Form", "  Esc cancels", nil
		}
		rows := make([]string, 0, len(m.form.fields)+2)
		for i, field := range m.form.fields {
			marker := "  "
			value := field.value
			if len(field.options) > 0 {
				value = "‹ " + value + " ›"
			} else if i == m.form.index {
				value += "▏"
			}
			if i == m.form.index {
				marker = brightCyan + "› " + reset
			}
			rows = append(rows, marker+fmt.Sprintf("%-18s  %s", field.label, tailFit(value, maxInt(inner-24, 8))))
		}
		rows = append(rows, "", green+"  Enter  Next / save"+reset+dim+"   •   Tab  Next field   •   ←/→  Change option"+reset)
		return m.form.title, "  Fill in each field; values are validated before saving", rows
	case "actions", "key_remove", "member_add", "member_remove":
		title := "Choose action"
		context := "  Enter selects • Esc returns"
		if m.mode == "key_remove" {
			title = "Remove SSH key"
		} else if m.mode == "member_add" {
			title = "Add group member"
		} else if m.mode == "member_remove" {
			title = "Remove group member"
		}
		rows := make([]string, 0, len(m.actions))
		for i, action := range m.actions {
			marker := "  "
			if i == m.actionCursor {
				marker = brightCyan + "› " + reset
			}
			rows = append(rows, marker+action.label)
		}
		return title, context, rows
	case "confirm_delete":
		name := "selected item"
		if m.pending != nil {
			switch m.pending.kind {
			case "target_delete":
				name = "target " + m.pending.target.Name
			case "user_delete":
				name = "user " + m.pending.username
			case "group_delete":
				name = "group " + m.pending.group
			case "grant_delete":
				name = "grant for " + m.pending.grant.Target
			case "identity_delete":
				name = "SSH key " + m.pending.identity.Name
			case "user_totp_remove":
				name = "TOTP for user " + m.pending.username
			}
		}
		return "Confirm removal", red + "  This change takes effect immediately" + reset, []string{"", "  Remove " + name + "?", "", red + "  y  Remove" + reset, dim + "  n  Keep it" + reset}
	case "public_key":
		return "Add SSH public key", "  Paste one OpenSSH public key", []string{"", fmt.Sprintf("  Public key captured: %d bytes", len(m.input)), "", green + "  Enter   Validate and save" + reset, dim + "  Ctrl+D  Also saves • Esc cancels" + reset}
	case "identity_public":
		if m.pending == nil {
			return "SSH public key", "  Press any key to return", nil
		}
		rows := []string{"  Name         " + m.pending.identity.Name, "  Fingerprint  " + m.pending.identity.Fingerprint, "", "  Public key:"}
		rows = append(rows, wrapText("  "+m.pending.identity.PublicKey, maxInt(inner-2, 16))...)
		return "SSH public key", "  Safe to copy to the downstream server", rows
	case "agent_key":
		return "Forwarded-agent identity", "  This public key pins the only agent identity SSHGateW may use", []string{"", fmt.Sprintf("  Public key captured: %d bytes", len(m.input)), "", green + "  Enter   Validate and save" + reset, dim + "  No private key is stored • Connect with ssh -A" + reset}
	case "confirm_host":
		fingerprint := "Unavailable"
		algorithm := ""
		if m.pending != nil && m.pending.hostKey != nil {
			fingerprint = gossh.FingerprintSHA256(m.pending.hostKey)
			algorithm = m.pending.hostKey.Type()
		}
		return "Confirm downstream host key", yellow + "  Verify this fingerprint out-of-band" + reset, []string{"  Algorithm    " + algorithm, "  Fingerprint  " + fingerprint, "", green + "  y  Accept and continue" + reset, red + "  n  Reject" + reset}
	case "scanning":
		return "Scanning host key", "  Connecting to the downstream SSH server…", []string{"", cyan + "  ◌ Waiting for host-key exchange" + reset, "", dim + "  Esc cancels this workflow" + reset}
	case "secret_password":
		return "Secure password input", "  Contents are never rendered or logged", []string{"", fmt.Sprintf("  %s  %d bytes captured", strings.Repeat("•", minInt(len(m.input), 24)), len(m.input)), "", green + "  Enter  Save credential" + reset, dim + "  Esc    Cancel" + reset}
	case "secret_key":
		return "Secure private-key input", "  Paste the key, then press Ctrl+D", []string{"", fmt.Sprintf("  Private key captured: %d bytes", len(m.input)), "", green + "  Ctrl+D  Validate and save" + reset, dim + "  Esc     Cancel" + reset}
	case "secret_passphrase":
		return "Private-key passphrase", "  Contents are never rendered or logged", []string{"", fmt.Sprintf("  %s  %d bytes captured", strings.Repeat("•", minInt(len(m.input), 24)), len(m.input)), "", green + "  Enter  Unlock and save" + reset, dim + "  Esc    Cancel" + reset}
	case "totp_confirm":
		secret, uri := "", ""
		if m.pending != nil {
			secret, uri = m.pending.totpSecret, m.pending.totpURI
		}
		rows := []string{"  Manual secret  " + secret, "", "  Setup URI:"}
		rows = append(rows, wrapText("  "+uri, maxInt(inner-2, 16))...)
		rows = append(rows, "", fmt.Sprintf("  %s  %d digits captured", strings.Repeat("•", minInt(len(m.input), 6)), len(m.input)), "", green+"  Enter  Verify and enable"+reset)
		return "Confirm TOTP enrollment", "  Enter the current six-digit authenticator code", rows
	case "totp_auth":
		return "Two-factor authentication", "  Public key accepted • TOTP required", []string{"", fmt.Sprintf("  %s  %d digits captured", strings.Repeat("•", minInt(len(m.input), 6)), len(m.input)), "", green + "  Enter  Verify" + reset, dim + "  Esc    Disconnect" + reset}
	default:
		return "Working", "  Please wait…", nil
	}
}

func (m *Model) statusLine(w int) string {
	if m.status == "" {
		return fit(dim+"  ● Ready"+reset, w)
	}
	lower := strings.ToLower(m.status)
	color := green
	if strings.Contains(lower, "fail") || strings.Contains(lower, "error") || strings.Contains(lower, "denied") || strings.Contains(lower, "invalid") {
		color = red
	} else if strings.Contains(lower, "cancel") || strings.Contains(lower, "verify") {
		color = yellow
	}
	return fit("  "+color+"● "+reset+m.status, w)
}
func (m *Model) footer() string {
	if m.mode != "" {
		if m.mode == "help" {
			return dim + "  Any key  close help" + reset
		}
		return dim + "  Esc  cancel" + reset
	}
	if m.searching {
		return dim + "  Type to filter  •  Enter apply  •  Esc clear" + reset
	}
	actions := "  ↑↓ navigate  •  Enter connect  •  / search  •  ? help  •  q quit"
	if m.user.Role == store.RoleAdmin {
		switch m.section {
		case "targets":
			actions = "  Enter connect  •  a add  •  m manage  •  / search  •  ←→ tabs  •  ? help"
		case "keys":
			actions = "  Enter/m manage  •  a add or generate  •  ←→ tabs  •  ? help  •  q quit"
		case "users", "groups":
			actions = "  Enter/m manage  •  a add  •  ←→ tabs  •  ? help  •  q quit"
		case "grants":
			actions = "  Enter/m manage  •  a grant access  •  ←→ tabs  •  ? help  •  q quit"
		default:
			actions = "  ↑↓ navigate  •  ←→ tabs  •  r refresh  •  ? help  •  q quit"
		}
	}
	return dim + actions + reset
}

func visibleRange(cursor, total, height int) (int, int) {
	if total <= 0 {
		return 0, 0
	}
	if height < 1 {
		height = 1
	}
	start := (cursor / height) * height
	if start+height > total {
		start = total - height
		if start < 0 {
			start = 0
		}
	}
	end := start + height
	if end > total {
		end = total
	}
	return start, end
}
func fit(s string, width int) string {
	if width <= 0 {
		return ""
	}
	s = ansi.Truncate(s, width, "…")
	if n := ansi.StringWidth(s); n < width {
		s += strings.Repeat(" ", width-n)
	}
	return s
}
func tailFit(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(s) <= width {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && ansi.StringWidth("…"+string(r)) > width {
		r = r[1:]
	}
	return "…" + string(r)
}
func wrapText(s string, width int) []string {
	if width < 1 {
		return []string{s}
	}
	runes := []rune(s)
	var lines []string
	for len(runes) > 0 {
		end := minInt(len(runes), width)
		lines = append(lines, string(runes[:end]))
		runes = runes[end:]
	}
	return lines
}
func joinSides(left, right string, width int) string {
	space := width - ansi.StringWidth(left) - ansi.StringWidth(right)
	if space < 1 {
		return fit(left+" "+right, width)
	}
	return left + strings.Repeat(" ", space) + right
}
func borderTop(label string, width int) string {
	inside := width - 2
	if inside < 1 {
		return fit("─", width)
	}
	middle := "─ " + ansi.Truncate(label, maxInt(1, inside-3), "…") + " "
	if n := ansi.StringWidth(middle); n < inside {
		middle += strings.Repeat("─", inside-n)
	}
	return dim + "┌" + middle + "┐" + reset
}
func borderBottom(width int) string {
	if width < 2 {
		return strings.Repeat("─", width)
	}
	return dim + "└" + strings.Repeat("─", width-2) + "┘" + reset
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
