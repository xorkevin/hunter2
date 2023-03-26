package h2signer

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/kerrors"
)

var (
	// ErrNotSupported is returned when t he signing key is not supported
	ErrNotSupported errNotSupported
	// ErrSigningKeyInvalid is returned when the signing key config is invalid
	ErrSigningKeyInvalid errSigningKeyInvalid
	// ErrVerifierKeyInvalid is returned when the verifier key config is invalid
	ErrVerifierKeyInvalid errVerifierKeyInvalid
)

type (
	errNotSupported       struct{}
	errSigningKeyInvalid  struct{}
	errVerifierKeyInvalid struct{}
)

func (e errNotSupported) Error() string {
	return "Signing key not supported"
}

func (e errSigningKeyInvalid) Error() string {
	return "Invalid signing key"
}

func (e errVerifierKeyInvalid) Error() string {
	return "Invalid verifier key"
}

type (
	// SigningKey is a signing key interface
	SigningKey interface {
		Alg() string
		ID() string
		Private() interface{}
		Public() interface{}
	}

	// VerifierKey is a verifier key interface
	VerifierKey interface {
		Alg() string
		ID() string
		Public() interface{}
	}

	// SigningKeyring holds signing keys
	SigningKeyring struct {
		keys map[string]SigningKey
	}

	// VerifierKeyring holds verifier keys
	VerifierKeyring struct {
		keys map[string]VerifierKey
	}
)

// NewSigningKeyring creates a new signing keyring
func NewSigningKeyring() *SigningKeyring {
	return &SigningKeyring{
		keys: map[string]SigningKey{},
	}
}

// Register registers a signing key
func (s *SigningKeyring) Register(k SigningKey) {
	s.keys[k.ID()] = k
}

// Get gets a registered signing key by id
func (s *SigningKeyring) Get(id string) (SigningKey, bool) {
	k, ok := s.keys[id]
	return k, ok
}

// Size returns the number of registered signing keys
func (s *SigningKeyring) Size() int {
	return len(s.keys)
}

// NewVerifierKeyring creates a new verifier keyring
func NewVerifierKeyring() *VerifierKeyring {
	return &VerifierKeyring{
		keys: map[string]VerifierKey{},
	}
}

// Register registers a verifier key
func (s *VerifierKeyring) Register(k VerifierKey) {
	s.keys[k.ID()] = k
}

// Get gets a registered verifier key by id
func (s *VerifierKeyring) Get(id string) (VerifierKey, bool) {
	k, ok := s.keys[id]
	return k, ok
}

// Size returns the number of registered verifier keys
func (s *VerifierKeyring) Size() int {
	return len(s.keys)
}

type (
	// SigningKeyBuilder constructs a new signing key from params
	SigningKeyBuilder interface {
		ID() string
		Build(params string) (SigningKey, error)
	}

	// SigningKeyAlgs are a map of valid signing keys
	SigningKeyAlgs interface {
		Register(b SigningKeyBuilder)
		Get(id string) (SigningKeyBuilder, bool)
	}

	SigningKeysMap struct {
		algs map[string]SigningKeyBuilder
	}

	// VerifierKeyBuilder constructs a new verifier key from params
	VerifierKeyBuilder interface {
		ID() string
		Build(params string) (VerifierKey, error)
	}

	// VerifierKeyAlgs are a map of valid verifier keys
	VerifierKeyAlgs interface {
		Register(b VerifierKeyBuilder)
		Get(id string) (VerifierKeyBuilder, bool)
	}

	VerifierKeysMap struct {
		algs map[string]VerifierKeyBuilder
	}
)

func NewSigningKeysMap() *SigningKeysMap {
	return &SigningKeysMap{
		algs: map[string]SigningKeyBuilder{},
	}
}

func (m *SigningKeysMap) Register(b SigningKeyBuilder) {
	m.algs[b.ID()] = b
}

func (m *SigningKeysMap) Get(id string) (SigningKeyBuilder, bool) {
	a, ok := m.algs[id]
	return a, ok
}

func NewVerifierKeysMap() *VerifierKeysMap {
	return &VerifierKeysMap{
		algs: map[string]VerifierKeyBuilder{},
	}
}

func (m *VerifierKeysMap) Register(b VerifierKeyBuilder) {
	m.algs[b.ID()] = b
}

func (m *VerifierKeysMap) Get(id string) (VerifierKeyBuilder, bool) {
	a, ok := m.algs[id]
	return a, ok
}

const (
	PEMBlockTypePrivateKey = "PRIVATE KEY"
	PEMBlockTypePublicKey  = "PUBLIC KEY"
)

// SigningKeyFromParams creates a cipher from params
func SigningKeyFromParams(params string, signingKeys SigningKeyAlgs) (SigningKey, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, ErrSigningKeyInvalid, "Invalid signing key")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	s, ok := signingKeys.Get(id)
	if !ok {
		return nil, kerrors.WithKind(nil, ErrNotSupported, fmt.Sprintf("Signing key not registered: %s", id))
	}
	k, err := s.Build(params)
	if err != nil {
		return nil, kerrors.WithKind(err, ErrSigningKeyInvalid, "Invalid signing key")
	}
	return k, nil
}

// VerifierKeyFromParams creates a verifier from params
func VerifierKeyFromParams(params string, verifierKeys VerifierKeyAlgs) (VerifierKey, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, ErrVerifierKeyInvalid, "Invalid verifier key")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	s, ok := verifierKeys.Get(id)
	if !ok {
		return nil, kerrors.WithKind(nil, ErrNotSupported, fmt.Sprintf("Verifier key not registered: %s", id))
	}
	k, err := s.Build(params)
	if err != nil {
		return nil, kerrors.WithKind(err, ErrVerifierKeyInvalid, "Invalid verifier key")
	}
	return k, nil
}

// KeyID computes a key id from params
func KeyID(params string) string {
	k := blake2b.Sum256([]byte(params))
	return base64.RawURLEncoding.EncodeToString(k[:])
}
