package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	Period = int64(30)
	Digits = 6
)

func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func URI(issuer, account, secret string) string {
	label := url.PathEscape(account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func Code(secret string, at time.Time) (string, int64, error) {
	counter := at.Unix() / Period
	code, err := codeAt(secret, counter)
	return code, counter, err
}

func Validate(secret, candidate string, at time.Time) (int64, bool) {
	candidate = strings.TrimSpace(candidate)
	if len(candidate) != Digits {
		return 0, false
	}
	counter := at.Unix() / Period
	for offset := int64(-1); offset <= 1; offset++ {
		expected, err := codeAt(secret, counter+offset)
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(candidate)) == 1 {
			return counter + offset, true
		}
	}
	return 0, false
}

func codeAt(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0"+strconv.Itoa(Digits)+"d", value%1_000_000), nil
}

// QR renders an otpauth URI using half-block characters, which preserves
// square QR modules on the common 1:2 terminal cell aspect ratio.
func QR(content string) ([]string, error) {
	qr, err := qrcode.New(content, qrcode.Low)
	if err != nil {
		return nil, err
	}
	qr.DisableBorder = true
	bitmap := qr.Bitmap()
	size := len(bitmap)
	quiet := 4
	lines := make([]string, 0, (size+quiet*2+1)/2)
	for y := -quiet; y < size+quiet; y += 2 {
		var line strings.Builder
		for x := -quiet; x < size+quiet; x++ {
			top := y >= 0 && y < size && x >= 0 && x < size && bitmap[y][x]
			bottom := y+1 >= 0 && y+1 < size && x >= 0 && x < size && bitmap[y+1][x]
			switch {
			case top && bottom:
				line.WriteRune('█')
			case top:
				line.WriteRune('▀')
			case bottom:
				line.WriteRune('▄')
			default:
				line.WriteByte(' ')
			}
		}
		lines = append(lines, line.String())
	}
	return lines, nil
}
