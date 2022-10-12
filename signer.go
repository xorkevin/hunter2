package hunter2

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

var (
	// ErrSigningKeyNotSupported is returned when t he signing key is not supported
	ErrSigningKeyNotSupported = errors.New("Signing key not supported")
	// ErrSigningKeyInvalid is returned when the signing key config is invalid
	ErrSigningKeyInvalid = errors.New("Invalid signing key")
)

type (
	// SigningKey is a signing key interface
	SigningKey interface {
		Alg() string
		ID() string
		Private() crypto.PrivateKey
		Public() crypto.PublicKey
	}

	// VerifierKey is a verifier key interface
	VerifierKey interface {
		Alg() string
		ID() string
		Public() crypto.PublicKey
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

// RegisterSigningKey registers a signing key
func (s *SigningKeyring) RegisterSigningKey(k SigningKey) {
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

// RegisterVerifierKey registers a verifier key
func (s *VerifierKeyring) RegisterVerifierKey(k VerifierKey) {
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
	// SigningKeyConstructor constructs a new signing key from params
	SigningKeyConstructor = func(params string) (SigningKey, error)

	// SigningKeyAlgs are a map of valid signing keys
	SigningKeyAlgs interface {
		Get(id string) (SigningKeyConstructor, bool)
	}

	signingKeysMap map[string]SigningKeyConstructor

	// VerifierKeyConstructor constructs a new verifier key from params
	VerifierKeyConstructor = func(params string) (VerifierKey, error)

	// VerifierKeyAlgs are a map of valid verifier keys
	VerifierKeyAlgs interface {
		Get(id string) (VerifierKeyConstructor, bool)
	}

	verifierKeysMap map[string]VerifierKeyConstructor
)

func (s signingKeysMap) Get(id string) (SigningKeyConstructor, bool) {
	a, ok := s[id]
	return a, ok
}

func (v verifierKeysMap) Get(id string) (VerifierKeyConstructor, bool) {
	a, ok := v[id]
	return a, ok
}

// Signing key algorithms
const (
	SigningAlgHS512 = "hs512"
	SigningAlgRS256 = "rs256"
	SigningAlgEdDSA = "eddsa"
)

const (
	privateKeyBlockType = "PRIVATE KEY"
	publicKeyBlockType  = "PUBLIC KEY"
)

var (
	// DefaultSigningKeyAlgs are the default supported signing key algs
	DefaultSigningKeyAlgs = signingKeysMap{
		SigningAlgHS512: HS512FromParams,
		SigningAlgRS256: RS256FromParams,
	}

	// DefaultVerifierKeyAlgs are the default supported signing key algs
	DefaultVerifierKeyAlgs = verifierKeysMap{
		SigningAlgEdDSA: EdDSAVerifierFromParams,
	}
)

// SigningKeyFromParams creates a cipher from params
func SigningKeyFromParams(params string, signingKeys SigningKeyAlgs) (SigningKey, error) {
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	s, ok := signingKeys.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s not registered", ErrSigningKeyNotSupported, id)
	}
	return s(params)
}

// VerifierKeyFromParams creates a verifier from params
func VerifierKeyFromParams(params string, verifierKeys VerifierKeyAlgs) (VerifierKey, error) {
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	s, ok := verifierKeys.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s not registered", ErrSigningKeyNotSupported, id)
	}
	return s(params)
}

func signingKeyID(params string) string {
	k := blake2b.Sum256([]byte(params))
	return base64.RawURLEncoding.EncodeToString(k[:])
}
