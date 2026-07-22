package tui

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	charmssh "github.com/charmbracelet/ssh"
)

const (
	enterScreen = "\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[H\x1b[2J"
	leaveScreen = "\x1b[?2004l\x1b[?25h\x1b[?1049l"
)

type readResult struct {
	data []byte
	err  error
}
type inputEvent struct{ key, paste string }

// RunRemote runs a Model directly on an SSH PTY. Reads are requested one at a
// time, ensuring no background reader survives to steal downstream keystrokes.
func RunRemote(ctx context.Context, rw io.ReadWriter, initial charmssh.Window, windows <-chan charmssh.Window, m *Model) (Result, error) {
	m.width, m.height = initial.Width, initial.Height
	applyMessage(m, reloadMsg{})
	if _, err := io.WriteString(rw, enterScreen); err != nil {
		return Result{}, err
	}
	defer io.WriteString(rw, leaveScreen)
	render := func() error {
		_, err := io.WriteString(rw, "\x1b[?2026h\x1b[H"+m.View().Content+"\x1b[J\x1b[?2026l")
		return err
	}
	if err := render(); err != nil {
		return Result{}, err
	}

	requests := make(chan struct{})
	reads := make(chan readResult, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			case <-requests:
			}
			n, err := rw.Read(buf)
			select {
			case reads <- readResult{data: append([]byte(nil), buf[:n]...), err: err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	requestRead := func() { requests <- struct{}{} }
	requestRead()
	var pending []byte
	for {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case window, open := <-windows:
			if !open {
				windows = nil
			} else if window.Width != m.width || window.Height != m.height {
				m.width, m.height = window.Width, window.Height
				if err := render(); err != nil {
					return Result{}, err
				}
			}
		case read := <-reads:
			if len(read.data) > 0 {
				pending = append(pending, read.data...)
				events, rest := parseInput(pending)
				pending = rest
				for _, event := range events {
					var cmd tea.Cmd
					if event.paste != "" {
						_, cmd = m.Update(tea.PasteMsg{Content: event.paste})
					} else {
						cmd = m.handleKey(event.key)
					}
					if m.result != nil {
						return *m.result, nil
					}
					if cmd != nil {
						// Show progress states (for example host-key scanning)
						// before executing a potentially blocking command.
						if err := render(); err != nil {
							return Result{}, err
						}
						applyCommand(m, cmd)
					}
					if err := render(); err != nil {
						return Result{}, err
					}
					if m.result != nil {
						return *m.result, nil
					}
				}
			}
			if read.err != nil {
				if errors.Is(read.err, io.EOF) {
					return Result{Quit: true}, nil
				}
				return Result{}, read.err
			}
			requestRead()
		}
	}
}

func applyMessage(m *Model, msg tea.Msg) {
	for msg != nil {
		_, cmd := m.Update(msg)
		if cmd == nil {
			return
		}
		msg = cmd()
	}
}
func applyCommand(m *Model, cmd tea.Cmd) {
	for cmd != nil {
		msg := cmd()
		_, cmd = m.Update(msg)
	}
}

func parseInput(data []byte) ([]inputEvent, []byte) {
	var events []inputEvent
	for len(data) > 0 {
		if len(data) == 1 && data[0] == 0x1b {
			events = append(events, inputEvent{key: "esc"})
			return events, nil
		}
		if strings.HasPrefix("\x1b[200~", string(data)) && len(data) < len("\x1b[200~") {
			return events, data
		}
		if strings.HasPrefix(string(data), "\x1b[200~") {
			end := strings.Index(string(data[6:]), "\x1b[201~")
			if end < 0 {
				return events, data
			}
			events = append(events, inputEvent{paste: string(data[6 : 6+end])})
			data = data[6+end+6:]
			continue
		}
		if data[0] == 0x1b {
			sequences := []struct{ raw, key string }{{"\x1b[A", "up"}, {"\x1b[B", "down"}, {"\x1b[C", "right"}, {"\x1b[D", "left"}, {"\x1b[5~", "pgup"}, {"\x1b[6~", "pgdown"}, {"\x1b[H", "home"}, {"\x1b[F", "end"}, {"\x1bOH", "home"}, {"\x1bOF", "end"}}
			matched, prefix := false, false
			for _, seq := range sequences {
				if strings.HasPrefix(seq.raw, string(data)) {
					prefix = true
				}
				if strings.HasPrefix(string(data), seq.raw) {
					events = append(events, inputEvent{key: seq.key})
					data = data[len(seq.raw):]
					matched = true
					break
				}
			}
			if matched {
				continue
			}
			if prefix {
				return events, data
			}
			if event, consumed, incomplete := parseExtendedKey(data); consumed > 0 {
				events = append(events, event)
				data = data[consumed:]
				continue
			} else if incomplete {
				return events, data
			}
			events = append(events, inputEvent{key: "esc"})
			data = data[1:]
			continue
		}
		switch data[0] {
		case 3:
			events = append(events, inputEvent{key: "ctrl+c"})
			data = data[1:]
			continue
		case 4:
			events = append(events, inputEvent{key: "ctrl+d"})
			data = data[1:]
			continue
		case 13, 10:
			events = append(events, inputEvent{key: "enter"})
			data = data[1:]
			continue
		case 8, 127:
			events = append(events, inputEvent{key: "backspace"})
			data = data[1:]
			continue
		case 9:
			events = append(events, inputEvent{key: "tab"})
			data = data[1:]
			continue
		case 21:
			events = append(events, inputEvent{key: "ctrl+u"})
			data = data[1:]
			continue
		case 32:
			events = append(events, inputEvent{key: "space"})
			data = data[1:]
			continue
		}
		if !utf8.FullRune(data) {
			return events, data
		}
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			data = data[1:]
			continue
		}
		events = append(events, inputEvent{key: string(r)})
		data = data[size:]
	}
	return events, nil
}

// parseExtendedKey decodes Kitty's CSI-u protocol and xterm's
// modifyOtherKeys form. Without this, sequences such as CSI 100;5u (Ctrl+D)
// look like Escape followed by printable characters: Escape cancels the modal
// and the modifier's "5" switches an administrator to the Audit tab.
func parseExtendedKey(data []byte) (inputEvent, int, bool) {
	if !strings.HasPrefix(string(data), "\x1b[") {
		return inputEvent{}, 0, false
	}
	for i := 2; i < len(data); i++ {
		if data[i] < 0x40 || data[i] > 0x7e {
			continue
		}
		final := data[i]
		body := string(data[2:i])
		if final == 'u' {
			fields := strings.Split(body, ";")
			if len(fields) == 0 {
				return inputEvent{}, 0, false
			}
			code, ok := leadingNumber(fields[0])
			if !ok {
				return inputEvent{}, 0, false
			}
			modifiers := 1
			if len(fields) > 1 {
				if parsed, valid := leadingNumber(fields[1]); valid {
					modifiers = parsed
				}
			}
			return inputEvent{key: extendedKeyName(code, modifiers)}, i + 1, false
		}
		if final == '~' {
			fields := strings.Split(body, ";")
			if len(fields) == 3 && fields[0] == "27" {
				modifiers, modOK := leadingNumber(fields[1])
				code, codeOK := leadingNumber(fields[2])
				if modOK && codeOK {
					return inputEvent{key: extendedKeyName(code, modifiers)}, i + 1, false
				}
			}
		}
		return inputEvent{}, 0, false
	}
	return inputEvent{}, 0, true
}

func leadingNumber(field string) (int, bool) {
	value := strings.SplitN(field, ":", 2)[0]
	n, err := strconv.Atoi(value)
	return n, err == nil
}

func extendedKeyName(code, modifiers int) string {
	if modifiers > 0 && (modifiers-1)&4 != 0 {
		return "ctrl+" + strings.ToLower(string(rune(code)))
	}
	switch code {
	case 9:
		return "tab"
	case 13:
		return "enter"
	case 27:
		return "esc"
	case 127:
		return "backspace"
	default:
		return string(rune(code))
	}
}
