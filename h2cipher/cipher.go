package h2cipher

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/kerrors"
)

var (
	// ErrorNotSupported is returned when the cipher is not supported
	ErrorNotSupported errorNotSupported
	// ErrorKeyInvalid is returned when the cipher key config is invalid
	ErrorKeyInvalid errorKeyInvalid
	// ErrorCiphertextInvalid is returned when the ciphertext is invalid
	ErrorCiphertextInvalid errorCiphertextInvalid
)

type (
	errorNotSupported      struct{}
	errorKeyInvalid        struct{}
	errorCiphertextInvalid struct{}
)

func (e errorNotSupported) Error() string {
	return "Cipher not supported"
}

func (e errorKeyInvalid) Error() string {
	return "Invalid cipher key"
}

func (e errorCiphertextInvalid) Error() string {
	return "Invalid ciphertext"
}

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
	if !strings.HasPrefix(ciphertext, "$") {
		return "", kerrors.WithKind(nil, ErrorCiphertextInvalid, "Invalid ciphertext")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(ciphertext, "$"), "$")
	cipher, ok := d.ciphers[id]
	if !ok {
		return "", kerrors.WithKind(nil, ErrorNotSupported, fmt.Sprintf("Cipher not registered: %s", id))
	}
	return cipher.Decrypt(ciphertext)
}

// Size returns the number of registered ciphers
func (d *Decrypter) Size() int {
	return len(d.ciphers)
}

type (
	// CipherConstructor constructs a new cipher from params
	CipherConstructor interface {
		Construct(params string) (Cipher, error)
	}

	CipherConstructorFunc func(params string) (Cipher, error)

	// CipherAlgs are a map of valid ciphers
	CipherAlgs interface {
		Get(id string) (CipherConstructor, bool)
	}

	CipherAlgsMap map[string]CipherConstructor
)

func (f CipherConstructorFunc) Construct(params string) (Cipher, error) {
	return f(params)
}

func (c CipherAlgsMap) Get(id string) (CipherConstructor, bool) {
	a, ok := c[id]
	return a, ok
}

// CipherFromParams creates a cipher from params
func CipherFromParams(params string, ciphers CipherAlgs) (Cipher, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, ErrorKeyInvalid, "Invalid cipher key")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	c, ok := ciphers.Get(id)
	if !ok {
		return nil, kerrors.WithKind(nil, ErrorNotSupported, fmt.Sprintf("Cipher not registered: %s", id))
	}
	return c.Construct(params)
}

// KeyID computes a key id from params
func KeyID(params string) string {
	k := blake2b.Sum256([]byte(params))
	return base64.RawURLEncoding.EncodeToString(k[:])
}
