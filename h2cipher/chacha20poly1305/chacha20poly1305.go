package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"xorkevin.dev/hunter2/h2cipher"
	"xorkevin.dev/kerrors"
)

const (
	CipherAlgID = "c20p"
)

type (
	// Config are chacha20-poly1305 params
	Config struct {
		Key []byte
	}
)

// NewConfig creates a new chacha20-poly1305 config
func NewConfig() (*Config, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate chacha20-poly1305 key")
	}
	return &Config{
		Key: key,
	}, nil
}

func (c Config) String() string {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(CipherAlgID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Key))
	return b.String()
}

// ParseConfig loads a chacha20-poly1305 config from params string
func ParseConfig(params string) (*Config, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2cipher.ErrorKeyInvalid, "Invalid chacha20-poly1305 key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != CipherAlgID {
		return nil, kerrors.WithKind(nil, h2cipher.ErrorKeyInvalid, "Invalid chacha20-poly1305 key")
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2cipher.ErrorKeyInvalid, "Invalid chacha20-poly1305 key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Cipher implements [h2cipher.Cipher] for chacha20-poly1305
	Cipher struct {
		kid    string
		cipher cipher.AEAD
	}
)

// New creates a new chacha20-poly1305 cipher
func New(config Config) (h2cipher.Cipher, error) {
	aead, err := chacha20poly1305.NewX(config.Key)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to create chacha20-poly1305 cipher")
	}
	return &Cipher{
		kid:    h2cipher.KeyID(config.String()),
		cipher: aead,
	}, nil
}

// NewFromParams creates a chacha20-poly1305 cipher from params
func NewFromParams(params string) (h2cipher.Cipher, error) {
	config, err := ParseConfig(params)
	if err != nil {
		return nil, err
	}
	return New(*config)
}

func (c *Cipher) ID() string {
	return c.kid
}

func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", kerrors.WithMsg(err, "Failed to create nonce")
	}
	ciphertext := c.cipher.Seal(nil, nonce, []byte(plaintext), nil)

	var b strings.Builder
	b.WriteString("$")
	b.WriteString(c.kid)
	b.WriteString("$")
	b.WriteString(CipherAlgID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(nonce))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(ciphertext))
	return b.String(), nil
}

func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, "$") {
		return "", kerrors.WithKind(nil, h2cipher.ErrorCiphertextInvalid, "Invalid chacha20-poly1305 ciphertext")
	}
	b := strings.Split(strings.TrimPrefix(ciphertext, "$"), "$")
	if len(b) != 4 || b[0] != c.kid || b[1] != CipherAlgID {
		return "", kerrors.WithKind(nil, h2cipher.ErrorCiphertextInvalid, "Invalid chacha20-poly1305 ciphertext")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return "", kerrors.WithKind(err, h2cipher.ErrorCiphertextInvalid, "Invalid chacha20-poly1305 nonce")
	}
	ciphertextbytes, err := base64.RawURLEncoding.DecodeString(b[3])
	if err != nil {
		return "", kerrors.WithKind(err, h2cipher.ErrorCiphertextInvalid, "Invalid chacha20-poly1305 ciphertext")
	}
	plaintext, err := c.cipher.Open(nil, nonce, ciphertextbytes, nil)
	if err != nil {
		return "", kerrors.WithKind(err, h2cipher.ErrorCiphertextInvalid, "Failed to decrypt")
	}
	return string(plaintext), nil
}
