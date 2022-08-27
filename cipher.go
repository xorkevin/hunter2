package hunter2

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

var (
	// ErrCipherNotSupported is returned when the cipher is not supported
	ErrCipherNotSupported = errors.New("Cipher not supported")
	// ErrCipherKeyInvalid is returned when the cipher key config is invalid
	ErrCipherKeyInvalid = errors.New("Cipher invalid key")
	// ErrCiphertextInvalid is returned when the ciphertext is invalid
	ErrCiphertextInvalid = errors.New("Cipher invalid ciphertext")
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
	id, _, _ := strings.Cut(strings.TrimPrefix(ciphertext, "$"), "$")
	cipher, ok := d.ciphers[id]
	if !ok {
		return "", fmt.Errorf("%w: %s not registered", ErrCipherNotSupported, id)
	}
	return cipher.Decrypt(ciphertext)
}

type (
	// CipherConstructor constructs a new cipher from params
	CipherConstructor = func(params string) (Cipher, error)

	// CipherAlgs are a map of valid ciphers
	CipherAlgs interface {
		Get(id string) (CipherConstructor, bool)
	}

	cipherAlgs map[string]CipherConstructor
)

func (c cipherAlgs) Get(id string) (CipherConstructor, bool) {
	a, ok := c[id]
	return a, ok
}

// Cipher algorithms
const (
	CipherAlgAES              = "aes"
	CipherAlgChaCha20Poly1305 = "cc20p"
)

var (
	// DefaultCipherAlgs are the default supported cipher algs
	DefaultCipherAlgs = cipherAlgs{
		CipherAlgAES:              AESCipherFromParams,
		CipherAlgChaCha20Poly1305: ChaCha20Poly1305CipherFromParams,
	}
)

// CipherFromParams creates a cipher from params
func CipherFromParams(params string, ciphers CipherAlgs) (Cipher, error) {
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	c, ok := ciphers.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s not registered", ErrCipherNotSupported, id)
	}
	return c(params)
}

func cipherKeyID(params string) string {
	k := blake2b.Sum256([]byte(params))
	return base64.RawURLEncoding.EncodeToString(k[:])
}
