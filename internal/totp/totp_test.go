package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestRFC6238SHA1VectorsTruncatedToSixDigits(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, test := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		got, _, err := Code(secret, time.Unix(test.unix, 0))
		if err != nil || got != test.want {
			t.Fatalf("time=%d code=%q want=%q err=%v", test.unix, got, test.want, err)
		}
		if _, valid := Validate(secret, got, time.Unix(test.unix, 0)); !valid {
			t.Fatalf("generated code rejected at %d", test.unix)
		}
	}
}

func TestEnrollmentURIAndTerminalQR(t *testing.T) {
	uri := URI("SSHGateW", "alice", "JBSWY3DPEHPK3PXP")
	if !strings.HasPrefix(uri, "otpauth://totp/alice?") || !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Fatalf("unexpected URI: %s", uri)
	}
	lines, err := QR(uri)
	if err != nil || len(lines) == 0 || len(lines) > 22 {
		t.Fatalf("QR lines=%d err=%v", len(lines), err)
	}
	width := len([]rune(lines[0]))
	for _, line := range lines {
		if len([]rune(line)) != width {
			t.Fatal("QR rows have inconsistent widths")
		}
	}
}
