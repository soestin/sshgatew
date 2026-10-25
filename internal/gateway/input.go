package gateway

import (
	"context"
	"io"

	charmssh "github.com/charmbracelet/ssh"
)

type inputResult struct {
	data []byte
	err  error
}

// interactiveSession owns the only reader of the SSH channel. Shell readers
// can be canceled without closing the channel or stealing the next menu key.
type interactiveSession struct {
	charmssh.Session
	reads   chan inputResult
	pending []byte
	err     error
}

func newInteractiveSession(sess charmssh.Session) *interactiveSession {
	s := &interactiveSession{Session: sess, reads: make(chan inputResult, 1)}
	go func() {
		defer close(s.reads)
		for {
			buf := make([]byte, 4096)
			n, err := sess.Read(buf)
			select {
			case s.reads <- inputResult{buf[:n], err}:
			case <-sess.Context().Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return s
}

func (s *interactiveSession) Read(p []byte) (int, error) {
	return s.ReadContext(s.Context(), p)
}

func (s *interactiveSession) PrependInput(p []byte) {
	s.pending = append(append([]byte(nil), p...), s.pending...)
}

// ReadContext has one consumer at a time; each shell joins its input worker
// before handing the session back to the menu.
func (s *interactiveSession) ReadContext(ctx context.Context, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if len(s.pending) > 0 {
			n := copy(p, s.pending)
			s.pending = s.pending[n:]
			return n, nil
		}
		if s.err != nil {
			return 0, s.err
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case r, ok := <-s.reads:
			if !ok {
				return 0, io.EOF
			}
			s.pending, s.err = r.data, r.err
		}
	}
}
