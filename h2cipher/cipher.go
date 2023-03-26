package h2cipher

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/kerrors"
)

var (
	// ErrNotSupported is returned when the cipher is not supported
	ErrNotSupported errNotSupported
	// ErrKeyInvalid is returned when the cipher key config is invalid
	ErrKeyInvalid errKeyInvalid
	// ErrCiphertextInvalid is returned when the ciphertext is invalid
	ErrCiphertextInvalid errCiphertextInvalid
)

type (
	errNotSupported      struct{}
	errKeyInvalid        struct{}
	errCiphertextInvalid struct{}
)

func (e errNotSupported) Error() string {
	return "Cipher not supported"
}

func (e errKeyInvalid) Error() string {
	return "Invalid cipher key"
}

func (e errCiphertextInvalid) Error() string {
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
		return nil, kerrors.WithKind(nil, ErrCiphertextInvalid, "Invalid ciphertext")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(ciphertext, "$"), "$")
	cipher, ok := k.ciphers[id]
	if !ok {
		return nil, kerrors.WithKind(nil, ErrNotSupported, fmt.Sprintf("Cipher not registered: %s", id))
	}
	plaintext, err := cipher.Decrypt(ciphertext)
	if err != nil {
		return nil, kerrors.WithKind(err, ErrCiphertextInvalid, "Failed to decrypt")
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
		return nil, kerrors.WithKind(nil, ErrKeyInvalid, "Invalid cipher key")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	a, ok := algs.Get(id)
	if !ok {
		return nil, kerrors.WithKind(nil, ErrNotSupported, fmt.Sprintf("Cipher not registered: %s", id))
	}
	c, err := a.Build(params)
	if err != nil {
		return nil, kerrors.WithKind(err, ErrKeyInvalid, "Invalid cipher key")
	}
	return c, nil
}

// KeyID computes a key id from params
func KeyID(params string) string {
	k := blake2b.Sum256([]byte(params))
	return base64.RawURLEncoding.EncodeToString(k[:])
}
