package tui

import "testing"

func TestParseInput(t *testing.T) {
	events, rest := parseInput([]byte("j\r\x1b[A\x7f"))
	if len(rest) != 0 || len(events) != 4 {
		t.Fatalf("events=%#v rest=%q", events, rest)
	}
	want := []string{"j", "enter", "up", "backspace"}
	for i, key := range want {
		if events[i].key != key {
			t.Fatalf("event %d=%q want %q", i, events[i].key, key)
		}
	}
}
func TestParseInputPreservesPartialEscape(t *testing.T) {
	events, rest := parseInput([]byte("\x1b["))
	if len(events) != 0 || string(rest) != "\x1b[" {
		t.Fatalf("events=%#v rest=%q", events, rest)
	}
	events, rest = parseInput(append(rest, 'B'))
	if len(rest) != 0 || len(events) != 1 || events[0].key != "down" {
		t.Fatalf("events=%#v rest=%q", events, rest)
	}
}
func TestParseLoneEscape(t *testing.T) {
	events, rest := parseInput([]byte("\x1b"))
	if len(rest) != 0 || len(events) != 1 || events[0].key != "esc" {
		t.Fatalf("events=%#v rest=%q", events, rest)
	}
}
func TestParseBracketedPaste(t *testing.T) {
	events, rest := parseInput([]byte("\x1b[200~secret\ntext\x1b[201~"))
	if len(rest) != 0 || len(events) != 1 || events[0].paste != "secret\ntext" {
		t.Fatalf("events=%#v rest=%q", events, rest)
	}
}

func TestParseKittyControlKeys(t *testing.T) {
	for _, test := range []struct {
		raw, key string
	}{
		{"\x1b[99;5u", "ctrl+c"},
		{"\x1b[100;5u", "ctrl+d"},
		{"\x1b[117;5u", "ctrl+u"},
		{"\x1b[120;5u", "ctrl+x"},
		{"\x1b[100;5:1u", "ctrl+d"},
		{"\x1b[100:68;5u", "ctrl+d"},
	} {
		events, rest := parseInput([]byte(test.raw))
		if len(rest) != 0 || len(events) != 1 || events[0].key != test.key {
			t.Errorf("parseInput(%q): events=%#v rest=%q, want %q", test.raw, events, rest, test.key)
		}
	}
}

func TestParseModifyOtherKeysControls(t *testing.T) {
	events, rest := parseInput([]byte("\x1b[27;5;100~"))
	if len(rest) != 0 || len(events) != 1 || events[0].key != "ctrl+d" {
		t.Fatalf("events=%#v rest=%q", events, rest)
	}
}

func TestParseFragmentedKittyControlKey(t *testing.T) {
	events, rest := parseInput([]byte("\x1b[100;"))
	if len(events) != 0 || string(rest) != "\x1b[100;" {
		t.Fatalf("partial events=%#v rest=%q", events, rest)
	}
	events, rest = parseInput(append(rest, []byte("5u")...))
	if len(rest) != 0 || len(events) != 1 || events[0].key != "ctrl+d" {
		t.Fatalf("completed events=%#v rest=%q", events, rest)
	}
}
