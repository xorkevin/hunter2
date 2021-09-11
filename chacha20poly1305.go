package hunter2

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

type (
	// ChaCha20Poly1305Config are chacha20-poly1305 params
	ChaCha20Poly1305Config struct {
		Key []byte
	}
)

// NewChaCha20Poly1305Config creates a new chacha20 poly1305 config
func NewChaCha20Poly1305Config() (*ChaCha20Poly1305Config, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("Failed to generate chacha20-poly1305 key: %w", err)
	}
	return &ChaCha20Poly1305Config{
		Key: key,
	}, nil
}

func (c ChaCha20Poly1305Config) String() string {
	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(CipherAlgChaCha20Poly1305)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Key))
	return b.String()
}

// ParseChaCha20Poly1305Config loads a chacha20-poly1305 config from params string
func ParseChaCha20Poly1305Config(params string) (*ChaCha20Poly1305Config, error) {
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != CipherAlgChaCha20Poly1305 {
		return nil, fmt.Errorf("%w: invalid params format", ErrCipherKeyInvalid)
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, fmt.Errorf("Invalid chacha20-poly1305 key: %w", err)
	}
	return &ChaCha20Poly1305Config{
		Key: key,
	}, nil
}

type (
	// ChaCha20Poly1305Cipher implements Cipher for chacha20-poly1305
	ChaCha20Poly1305Cipher struct {
		kid    string
		cipher cipher.AEAD
	}
)

// NewChaCha20Poly1305Cipher creates a new chacha20-poly1305 cipher
func NewChaCha20Poly1305Cipher(config ChaCha20Poly1305Config) (Cipher, error) {
	aead, err := chacha20poly1305.NewX(config.Key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create chacha20-poly1305 cipher: %w", err)
	}
	return &ChaCha20Poly1305Cipher{
		kid:    cipherKeyID(config.String()),
		cipher: aead,
	}, nil
}

// ChaCha20Poly1305CipherFromParams creates a chacha20-poly1305 cipher from params
func ChaCha20Poly1305CipherFromParams(params string) (Cipher, error) {
	config, err := ParseChaCha20Poly1305Config(params)
	if err != nil {
		return nil, err
	}
	return NewChaCha20Poly1305Cipher(*config)
}

func (c *ChaCha20Poly1305Cipher) ID() string {
	return c.kid
}

func (c *ChaCha20Poly1305Cipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("Failed to create nonce: %w", err)
	}
	ciphertext := c.cipher.Seal(nil, nonce, []byte(plaintext), nil)

	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(c.kid)
	b.WriteString("$")
	b.WriteString(CipherAlgChaCha20Poly1305)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(nonce))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(ciphertext))
	return b.String(), nil
}

func (c *ChaCha20Poly1305Cipher) Decrypt(ciphertext string) (string, error) {
	b := strings.Split(strings.TrimPrefix(ciphertext, "$"), "$")
	if len(b) != 4 || b[0] != c.kid || b[1] != CipherAlgChaCha20Poly1305 {
		return "", fmt.Errorf("%w: invalid chacha20-poly1305 ciphertext format", ErrCiphertextInvalid)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return "", fmt.Errorf("Invalid nonce: %w", err)
	}
	ciphertextbytes, err := base64.RawURLEncoding.DecodeString(b[3])
	if err != nil {
		return "", fmt.Errorf("Invalid nonce: %w", err)
	}
	plaintext, err := c.cipher.Open(nil, nonce, ciphertextbytes, nil)
	if err != nil {
		return "", fmt.Errorf("Invalid ciphtertext: %w", err)
	}
	return string(plaintext), nil
}
