package downstream

import "testing"

func TestSafeSCPCommand(t *testing.T) {
	tests := []struct {
		raw string
		ok  bool
	}{
		{"scp -t /tmp/file", true}, {"scp -prf '/tmp/a b'", true},
		{"scp -t /tmp/x;id", true}, {"scp -t /tmp/x ; id", false}, {"rm -rf /", false}, {"scp -v -t /tmp", false},
		{"scp -f -t /tmp", false}, {"scp -r /tmp", false}, {"scp -t /tmp\nwhoami", false},
	}
	for _, tt := range tests {
		_, err := SafeSCPCommand(tt.raw)
		if (err == nil) != tt.ok {
			t.Errorf("SafeSCPCommand(%q) err=%v", tt.raw, err)
		}
	}
}
