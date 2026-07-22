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

func (c *Cipher) Encrypt(targetID int64, kind string, p Payload) ([]byte, []byte, error) {
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
	return nonce, aead.Seal(nil, nonce, plain, aad(targetID, kind)), nil
}

func (c *Cipher) Decrypt(targetID int64, kind string, nonce, ciphertext []byte) (Payload, error) {
	aead, err := chacha20poly1305.NewX(c.key[:])
	if err != nil {
		return Payload{}, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, aad(targetID, kind))
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
