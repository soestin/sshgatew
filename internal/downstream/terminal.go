package downstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	charmssh "github.com/charmbracelet/ssh"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	gossh "golang.org/x/crypto/ssh"
)

var ErrTerminalBusy = errors.New("terminal is already attached in another connection")

// Terminal owns a downstream PTY independently of any gateway login. Only its
// current screen is retained, in memory; output is never written to disk.
type Terminal struct {
	client    *gossh.Client
	session   *gossh.Session
	stdin     io.WriteCloser
	input     chan []byte
	done      chan struct{}
	changed   chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	screen    *vt.Emulator
	modes     map[ansi.Mode]bool
	attached  bool
	err       error
}

var inputModes = []ansi.Mode{
	ansi.ModeCursorKeys, ansi.ModeNumericKeypad, ansi.ModeBracketedPaste,
	ansi.ModeMouseX10, ansi.ModeMouseNormal, ansi.ModeMouseButtonEvent,
	ansi.ModeMouseAnyEvent, ansi.ModeMouseExtSgr, ansi.ModeFocusEvent,
}

const resetTerminal = "\x1b[0m\x1b[?1l\x1b[?66l\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1006l\x1b[?2004l\x1b[?25h\x1b[?1049l"

func terminalSize(w charmssh.Window) (int, int) {
	width, height := w.Width, w.Height
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	return min(width, 300), min(height, 100)
}

// StartTerminal takes ownership of client on success. No inbound reader or
// login context is retained by the terminal.
func StartTerminal(client *gossh.Client, pty charmssh.Pty) (*Terminal, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	w, h := terminalSize(pty.Window)
	if err = session.RequestPty("xterm-256color", h, w, gossh.TerminalModes{gossh.ECHO: 1}); err != nil {
		session.Close()
		return nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, err
	}
	t := &Terminal{client: client, session: session, stdin: stdin, input: make(chan []byte, 64), done: make(chan struct{}), changed: make(chan struct{}, 1), screen: vt.NewEmulator(w, h), modes: make(map[ansi.Mode]bool)}
	t.screen.SetScrollbackSize(0)
	t.screen.SetCallbacks(vt.Callbacks{EnableMode: func(m ansi.Mode) {
		for _, allowed := range inputModes {
			if m == allowed {
				t.modes[m] = true
				break
			}
		}
	}, DisableMode: func(m ansi.Mode) { delete(t.modes, m) }})
	// The emulator answers terminal queries even while detached. Its pipe is
	// closed before Emulator.Close, avoiding concurrent access to its closed flag.
	repliesDone := make(chan struct{})
	go func() {
		defer close(repliesDone)
		buf := make([]byte, 4096)
		for {
			n, err := t.screen.Read(buf)
			if n > 0 {
				t.Send(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case data := <-t.input:
				if _, err := stdin.Write(data); err != nil {
					return
				}
			case <-t.done:
				return
			}
		}
	}()
	session.Stdout, session.Stderr = t, t
	if err = session.Shell(); err != nil {
		_ = t.screen.InputPipe().(io.Closer).Close()
		<-repliesDone
		_ = t.screen.Close()
		session.Close()
		close(t.done)
		return nil, err
	}
	go func() {
		err := session.Wait()
		_ = t.screen.InputPipe().(io.Closer).Close()
		<-repliesDone
		t.mu.Lock()
		t.err = err
		_ = t.screen.Close()
		t.mu.Unlock()
		t.Close()
		close(t.done)
	}()
	return t, nil
}

func (t *Terminal) Done() <-chan struct{} { return t.done }
func (t *Terminal) Close()                { t.closeOnce.Do(func() { _ = t.client.Close() }) }
func (t *Terminal) Busy() bool            { t.mu.Lock(); defer t.mu.Unlock(); return t.attached }
func (t *Terminal) Err() error            { t.mu.Lock(); defer t.mu.Unlock(); return t.err }

func (t *Terminal) Send(p []byte) error {
	select {
	case <-t.done:
		return io.EOF
	default:
	}
	select {
	case t.input <- bytes.Clone(p):
		return nil
	case <-t.done:
		return io.EOF
	default:
		t.Close()
		return errors.New("terminal input queue is full")
	}
}

func (t *Terminal) Write(p []byte) (int, error) {
	t.mu.Lock()
	n, err := t.screen.Write(p)
	t.mu.Unlock()
	select {
	case t.changed <- struct{}{}:
	default:
	}
	return n, err
}

func (t *Terminal) resize(window charmssh.Window) error {
	w, h := terminalSize(window)
	t.mu.Lock()
	t.screen.Resize(w, h)
	t.mu.Unlock()
	return t.session.WindowChange(h, w)
}

func (t *Terminal) snapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.screen.CursorPosition()
	var modes strings.Builder
	for _, m := range inputModes {
		if t.modes[m] {
			modes.WriteString(ansi.SetMode(m))
		} else {
			modes.WriteString(ansi.ResetMode(m))
		}
	}
	style, blink := t.screen.CursorStyle()
	cursorStyle := int(style)*2 + 1
	if !blink {
		cursorStyle++
	}
	visible := "\x1b[?25h"
	if t.screen.CursorHidden() {
		visible = "\x1b[?25l"
	}
	return "\x1b[?2026h\x1b[?25l\x1b[H\x1b[0m" + strings.ReplaceAll(t.screen.Render(), "\n", "\r\n") + "\x1b[J\x1b[0m" + fmt.Sprintf("\x1b[%d;%dH\x1b[%d q", p.Y+1, p.X+1, cursorStyle) + modes.String() + visible + "\x1b[?2026l"
}

type TerminalInput interface {
	ReadContext(context.Context, []byte) (int, error)
	PrependInput([]byte)
}

// Attach returns detached=true on Ctrl+] or loss of the inbound login. The
// downstream shell stays alive. A new attachment never steals an active one.
func (t *Terminal) Attach(ctx context.Context, inbound charmssh.Session, input TerminalInput, windows <-chan charmssh.Window) (detached bool, err error) {
	t.mu.Lock()
	if t.attached {
		t.mu.Unlock()
		return false, ErrTerminalBusy
	}
	t.attached = true
	t.mu.Unlock()
	defer func() { t.mu.Lock(); t.attached = false; t.mu.Unlock() }()
	pty, _, _ := inbound.Pty()
	// A shell may exit between creation and attachment. Still render its final
	// screen and let Wait report the actual exit status rather than a resize EOF.
	_ = t.resize(pty.Window)
	if _, err := io.WriteString(inbound, "\r\nCtrl+] detaches this terminal; exit closes its shell.\r\n\x1b[?1049h\x1b[?6l\x1b[r\x1b[2J"+t.snapshot()); err != nil {
		return true, err
	}
	defer io.WriteString(inbound, resetTerminal)
	readCtx, cancel := context.WithCancel(ctx)
	reads := make(chan inputResult)
	next := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		for {
			n, err := input.ReadContext(readCtx, buf)
			select {
			case reads <- inputResult{bytes.Clone(buf[:n]), err}:
			case <-readCtx.Done():
				return
			}
			if err != nil {
				return
			}
			select {
			case <-next:
			case <-readCtx.Done():
				return
			}
		}
	}()
	defer func() { cancel(); <-readDone }()
	signals := make(chan charmssh.Signal, 16)
	inbound.Signals(signals)
	defer inbound.Signals(nil)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	dirty := false
	var pending []byte
	var pendingSince time.Time
	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-t.done:
			_, _ = io.WriteString(inbound, t.snapshot())
			return false, t.Err()
		case <-t.changed:
			dirty = true
		case <-ticker.C:
			// A lone Escape must reach editors even if no further key arrives.
			// Only hold it briefly to recognize a fragmented extended Ctrl+].
			if len(pending) > 0 && time.Since(pendingSince) >= 50*time.Millisecond {
				if err := t.Send(pending); err != nil {
					return false, err
				}
				pending = nil
			}
			if dirty {
				if _, err := io.WriteString(inbound, t.snapshot()); err != nil {
					return true, err
				}
				dirty = false
			}
		case w, ok := <-windows:
			if !ok {
				windows = nil
			} else {
				_ = t.resize(w)
				dirty = true
			}
		case sig, ok := <-signals:
			if !ok {
				signals = nil
			} else {
				_ = t.session.Signal(gossh.Signal(sig))
			}
		case r := <-reads:
			pending = append(pending, r.data...)
			data, rest, detach, tail := splitDetach(pending)
			if len(data) > 0 {
				if err := t.Send(data); err != nil {
					return false, err
				}
			}
			pending = rest
			pendingSince = time.Now()
			if detach {
				input.PrependInput(tail)
				return true, nil
			}
			if r.err != nil {
				return true, r.err
			}
			select {
			case next <- struct{}{}:
			case <-readCtx.Done():
				return true, readCtx.Err()
			}
		}
	}
}

type inputResult struct {
	data []byte
	err  error
}

// Recognize both ordinary terminal input and Kitty/modifyOtherKeys Ctrl+].
func splitDetach(p []byte) (data, rest []byte, detach bool, tail []byte) {
	sequences := [][]byte{{0x1d}, []byte("\x1b[93;5u"), []byte("\x1b[93;5:1u"), []byte("\x1b[27;5;93~")}
	for i := range p {
		for _, seq := range sequences {
			if bytes.HasPrefix(p[i:], seq) {
				return p[:i], nil, true, p[i+len(seq):]
			}
			if bytes.HasPrefix(seq, p[i:]) {
				return p[:i], bytes.Clone(p[i:]), false, nil
			}
		}
	}
	return p, nil, false, nil
}
