package hunter2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

type (
	// AESConfig are aes params
	AESConfig struct {
		kid string
		key []byte
	}
)

// NewAESConfig creates a new aes config
func NewAESConfig(kid string, keylen int) (*AESConfig, error) {
	key := make([]byte, keylen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &AESConfig{
		kid: kid,
		key: key,
	}, nil
}

func (c AESConfig) String() string {
	b := strings.Builder{}
	b.WriteString("$aes$")
	b.WriteString(c.kid)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.key))
	return b.String()
}

// ParseAESConfig loads an aes config from params string
func ParseAESConfig(params string) (*AESConfig, error) {
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 3 || b[0] != "aes" {
		return nil, fmt.Errorf("%w: invalid params format", ErrCipherKeyInvalid)
	}
	kid := b[1]
	key, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid aes key", ErrCipherKeyInvalid)
	}
	return &AESConfig{
		kid: kid,
		key: key,
	}, nil
}

type (
	// AESCipher implements Cipher for aes
	AESCipher struct {
		kid    string
		cipher cipher.AEAD
	}
)

// NewAESCipher creates a new aes cipher
func NewAESCipher(config AESConfig) (*AESCipher, error) {
	block, err := aes.NewCipher(config.key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to create aes gcm: %w", err)
	}
	return &AESCipher{
		kid:    config.kid,
		cipher: gcm,
	}, nil
}

// AESCipherFromParams creates an aes cipher from params
func AESCipherFromParams(params string) (*AESCipher, error) {
	config, err := ParseAESConfig(params)
	if err != nil {
		return nil, err
	}
	return NewAESCipher(*config)
}

func (c *AESCipher) ID() string {
	return c.kid
}

// Encrypt encrypts using aes
//
// Security paramter is 2^32 random nonce uses.
func (c *AESCipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("Failed to create nonce: %w", err)
	}
	ciphertext := c.cipher.Seal(nil, nonce, []byte(plaintext), nil)

	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(c.kid)
	b.WriteString("$aes$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(nonce))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(ciphertext))
	return b.String(), nil
}

func (c *AESCipher) Decrypt(ciphertext string) (string, error) {
	b := strings.Split(strings.TrimPrefix(ciphertext, "$"), "$")
	if len(b) != 4 || b[0] != c.kid || b[1] != "aes" {
		return "", fmt.Errorf("%w: invalid aes ciphertext format", ErrCiphertextInvalid)
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
