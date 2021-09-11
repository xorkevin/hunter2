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
		Key []byte
	}
)

// NewAESConfig creates a new aes config
func NewAESConfig() (*AESConfig, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("Failed to generate aes key: %w", err)
	}
	return &AESConfig{
		Key: key,
	}, nil
}

func (c AESConfig) String() string {
	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(CipherAlgAES)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Key))
	return b.String()
}

// ParseAESConfig loads an aes config from params string
func ParseAESConfig(params string) (*AESConfig, error) {
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != CipherAlgAES {
		return nil, fmt.Errorf("%w: invalid params format", ErrCipherKeyInvalid)
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, fmt.Errorf("Invalid aes key: %w", err)
	}
	return &AESConfig{
		Key: key,
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
func NewAESCipher(config AESConfig) (Cipher, error) {
	block, err := aes.NewCipher(config.Key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to create aes gcm: %w", err)
	}
	return &AESCipher{
		kid:    cipherKeyID(config.String()),
		cipher: aead,
	}, nil
}

// AESCipherFromParams creates an aes cipher from params
func AESCipherFromParams(params string) (Cipher, error) {
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
	b.WriteString("$")
	b.WriteString(CipherAlgAES)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(nonce))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(ciphertext))
	return b.String(), nil
}

func (c *AESCipher) Decrypt(ciphertext string) (string, error) {
	b := strings.Split(strings.TrimPrefix(ciphertext, "$"), "$")
	if len(b) != 4 || b[0] != c.kid || b[1] != CipherAlgAES {
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
