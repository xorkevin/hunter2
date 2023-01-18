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
		Encrypt(plaintext []byte) (string, error)
		Decrypt(ciphertext string) ([]byte, error)
	}

	// Keyring decrypts ciphertext
	Keyring struct {
		ciphers map[string]Cipher
	}
)

// NewKeyring creates a new decrypter
func NewKeyring() *Keyring {
	return &Keyring{
		ciphers: map[string]Cipher{},
	}
}

// Register registers a Cipher
func (k *Keyring) Register(cipher Cipher) {
	k.ciphers[cipher.ID()] = cipher
}

// Decrypt finds the cipher by id and returns plaintext
func (k *Keyring) Decrypt(ciphertext string) ([]byte, error) {
	if !strings.HasPrefix(ciphertext, "$") {
		return nil, kerrors.WithKind(nil, ErrorCiphertextInvalid, "Invalid ciphertext")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(ciphertext, "$"), "$")
	cipher, ok := k.ciphers[id]
	if !ok {
		return nil, kerrors.WithKind(nil, ErrorNotSupported, fmt.Sprintf("Cipher not registered: %s", id))
	}
	plaintext, err := cipher.Decrypt(ciphertext)
	if err != nil {
		return nil, kerrors.WithKind(err, ErrorCiphertextInvalid, "Failed to decrypt")
	}
	return plaintext, nil
}

// Size returns the number of registered ciphers
func (k *Keyring) Size() int {
	return len(k.ciphers)
}

type (
	// Builder constructs a new cipher from params
	Builder interface {
		ID() string
		Build(params string) (Cipher, error)
	}

	// Algs are a map of valid cipher algorithms
	Algs interface {
		Register(b Builder)
		Get(id string) (Builder, bool)
	}

	AlgsMap struct {
		algs map[string]Builder
	}
)

func NewAlgsMap() *AlgsMap {
	return &AlgsMap{
		algs: map[string]Builder{},
	}
}

func (m *AlgsMap) Register(b Builder) {
	m.algs[b.ID()] = b
}

func (m *AlgsMap) Get(id string) (Builder, bool) {
	a, ok := m.algs[id]
	return a, ok
}

// FromParams creates a cipher from params
func FromParams(params string, algs Algs) (Cipher, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, ErrorKeyInvalid, "Invalid cipher key")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	a, ok := algs.Get(id)
	if !ok {
		return nil, kerrors.WithKind(nil, ErrorNotSupported, fmt.Sprintf("Cipher not registered: %s", id))
	}
	c, err := a.Build(params)
	if err != nil {
		return nil, kerrors.WithKind(err, ErrorKeyInvalid, "Invalid cipher key")
	}
	return c, nil
}

// KeyID computes a key id from params
func KeyID(params string) string {
	k := blake2b.Sum256([]byte(params))
	return base64.RawURLEncoding.EncodeToString(k[:])
}
