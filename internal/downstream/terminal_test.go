package downstream

import (
	"strings"
	"testing"
)

func TestSplitDetach(t *testing.T) {
	for _, sequence := range []string{"\x1d", "\x1b[93;5u", "\x1b[93;5:1u", "\x1b[27;5;93~"} {
		for split := 0; split < len(sequence); split++ {
			first := []byte("before" + sequence[:split])
			data, rest, detached, _ := splitDetach(first)
			if detached {
				t.Fatalf("premature detach at %d in %q", split, sequence)
			}
			second := append(rest, []byte(sequence[split:]+"after")...)
			more, _, detached, tail := splitDetach(second)
			if !detached || string(append(data, more...)) != "before" || string(tail) != "after" {
				t.Fatalf("fragment %d of %q: data=%q rest=%q detach=%v tail=%q", split, sequence, data, more, detached, tail)
			}
		}
	}
	data, rest, detached, _ := splitDetach([]byte("\x1b[Ahello\x1b[200~paste\x1b[201~"))
	if detached || len(rest) != 0 || !strings.Contains(string(data), "paste") {
		t.Fatal("ordinary terminal input was interpreted as detach")
	}
}
