package gateway

import "testing"

func TestSplitRoutedUsername(t *testing.T) {
	tests := []struct {
		in, user, target string
		ok               bool
	}{{"alice", "alice", "", true}, {"Alice+Prod", "alice", "prod", true}, {"alice+prod+extra", "", "", false}, {"+prod", "", "", false}}
	for _, tt := range tests {
		u, target, err := splitRoutedUsername(tt.in)
		if (err == nil) != tt.ok || u != tt.user || target != tt.target {
			t.Errorf("splitRoutedUsername(%q)=(%q,%q,%v)", tt.in, u, target, err)
		}
	}
}
