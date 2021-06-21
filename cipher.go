package hunter2

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrCipherNotSupported = errors.New("Cipher not supported")
)

type (
	// Cipher is an encryption interface
	Cipher interface {
		ID() string
		Encrypt(plaintext string) (string, error)
		Decrypt(ciphertext string) (string, error)
	}

	// Decrypter decrypts ciphertext
	Decrypter struct {
		ciphers map[string]Cipher
	}
)

// NewDecrypter creates a new decrypter
func NewDecrypter() *Decrypter {
	return &Decrypter{
		ciphers: map[string]Cipher{},
	}
}

// RegisterCipher registers a Cipher
func (d *Decrypter) RegisterCipher(cipher Cipher) {
	d.ciphers[cipher.ID()] = cipher
}

// Decrypt finds the cipher by id and returns plaintext
func (d *Decrypter) Decrypt(ciphertext string) (string, error) {
	b := strings.SplitN(strings.TrimPrefix(ciphertext, "$"), "$", 2)
	cipher, ok := d.ciphers[b[0]]
	if !ok {
		return "", fmt.Errorf("%w: %s not registered", ErrCipherNotSupported, b[0])
	}
	return cipher.Decrypt(ciphertext)
}
