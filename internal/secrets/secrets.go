package secrets

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

type Cipher struct {
	key [chacha20poly1305.KeySize]byte
}

type Payload struct {
	Version    int    `json:"version"`
	Password   string `json:"password,omitempty"`
	PrivateKey []byte `json:"private_key,omitempty"`
	PublicKey  []byte `json:"public_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

func Generate(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	b := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

func Load(path string) (*Cipher, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("master key must be a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("master key permissions %04o are too open; require 0600", info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("master key must be exactly %d bytes", chacha20poly1305.KeySize)
	}
	c := &Cipher{}
	copy(c.key[:], b)
	zero(b)
	return c, nil
}

func aad(targetID int64, kind string) []byte {
	return []byte(fmt.Sprintf("sshgatew:credential:v1:%d:%s", targetID, kind))
}

func identityAAD(identityID int64) []byte {
	return []byte(fmt.Sprintf("sshgatew:ssh-identity:v1:%d", identityID))
}

func totpAAD(userID int64) []byte {
	return []byte(fmt.Sprintf("sshgatew:user-totp:v1:%d", userID))
}

func (c *Cipher) Encrypt(targetID int64, kind string, p Payload) ([]byte, []byte, error) {
	return c.encrypt(p, aad(targetID, kind))
}

func (c *Cipher) Decrypt(targetID int64, kind string, nonce, ciphertext []byte) (Payload, error) {
	return c.decrypt(nonce, ciphertext, aad(targetID, kind))
}

func (c *Cipher) EncryptSSHIdentity(identityID int64, p Payload) ([]byte, []byte, error) {
	return c.encrypt(p, identityAAD(identityID))
}

func (c *Cipher) DecryptSSHIdentity(identityID int64, nonce, ciphertext []byte) (Payload, error) {
	return c.decrypt(nonce, ciphertext, identityAAD(identityID))
}

func (c *Cipher) EncryptTOTP(userID int64, secret string) ([]byte, []byte, error) {
	return c.encrypt(Payload{TOTPSecret: secret}, totpAAD(userID))
}

func (c *Cipher) DecryptTOTP(userID int64, nonce, ciphertext []byte) (string, error) {
	payload, err := c.decrypt(nonce, ciphertext, totpAAD(userID))
	if err != nil {
		return "", err
	}
	if payload.TOTPSecret == "" {
		return "", errors.New("TOTP payload is empty")
	}
	return payload.TOTPSecret, nil
}

func (c *Cipher) encrypt(p Payload, associatedData []byte) ([]byte, []byte, error) {
	p.Version = 1
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	defer zero(plain)
	aead, err := chacha20poly1305.NewX(c.key[:])
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plain, associatedData), nil
}

func (c *Cipher) decrypt(nonce, ciphertext, associatedData []byte) (Payload, error) {
	aead, err := chacha20poly1305.NewX(c.key[:])
	if err != nil {
		return Payload{}, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return Payload{}, errors.New("credential authentication failed")
	}
	defer zero(plain)
	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return Payload{}, errors.New("credential payload is corrupt")
	}
	if p.Version != 1 {
		return Payload{}, fmt.Errorf("unsupported credential payload version %d", p.Version)
	}
	return p, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
