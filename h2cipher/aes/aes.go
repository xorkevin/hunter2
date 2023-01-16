package h2cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"xorkevin.dev/hunter2/h2cipher"
	"xorkevin.dev/kerrors"
)

const (
	CipherID = "aes"
)

type (
	// Config are aes params
	Config struct {
		Key []byte
	}
)

// NewConfig creates a new aes config
func NewConfig() (*Config, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate aes key")
	}
	return &Config{
		Key: key,
	}, nil
}

func (c Config) String() string {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(CipherID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Key))
	return b.String()
}

// ParseConfig loads an aes config from params string
func ParseConfig(params string) (*Config, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2cipher.ErrorKeyInvalid, "Invalid aes key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != CipherID {
		return nil, kerrors.WithKind(nil, h2cipher.ErrorKeyInvalid, "Invalid aes key")
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2cipher.ErrorKeyInvalid, "Invalid aes key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Cipher implements [h2cipher.Cipher] for aes
	Cipher struct {
		kid    string
		cipher cipher.AEAD
	}
)

// New creates a new aes cipher
func New(config Config) (*Cipher, error) {
	block, err := aes.NewCipher(config.Key)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to create aes cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to create aes gcm")
	}
	return &Cipher{
		kid:    h2cipher.KeyID(config.String()),
		cipher: aead,
	}, nil
}

// NewFromParams creates an aes cipher from params
func NewFromParams(params string) (*Cipher, error) {
	config, err := ParseConfig(params)
	if err != nil {
		return nil, err
	}
	return New(*config)
}

type (
	builder struct{}
)

func (b builder) ID() string {
	return CipherID
}

func (b builder) Build(params string) (h2cipher.Cipher, error) {
	return NewFromParams(params)
}

// Register registers a cipher alg
func Register(algs h2cipher.Algs) {
	algs.Register(builder{})
}

func (c *Cipher) ID() string {
	return c.kid
}

// Encrypt encrypts using aes
//
// Security paramter is 2^32 random nonce uses.
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
	b.WriteString(CipherID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(nonce))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(ciphertext))
	return b.String(), nil
}

func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, "$") {
		return "", kerrors.WithKind(nil, h2cipher.ErrorCiphertextInvalid, "Invalid aes ciphertext")
	}
	b := strings.Split(strings.TrimPrefix(ciphertext, "$"), "$")
	if len(b) != 4 || b[0] != c.kid || b[1] != CipherID {
		return "", kerrors.WithKind(nil, h2cipher.ErrorCiphertextInvalid, "Invalid aes ciphertext")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return "", kerrors.WithKind(err, h2cipher.ErrorCiphertextInvalid, "Invalid aes nonce")
	}
	ciphertextbytes, err := base64.RawURLEncoding.DecodeString(b[3])
	if err != nil {
		return "", kerrors.WithKind(err, h2cipher.ErrorCiphertextInvalid, "Invalid aes ciphertext")
	}
	plaintext, err := c.cipher.Open(nil, nonce, ciphertextbytes, nil)
	if err != nil {
		return "", kerrors.WithKind(err, h2cipher.ErrorCiphertextInvalid, "Failed to decrypt aes")
	}
	return string(plaintext), nil
}
