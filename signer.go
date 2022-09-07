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

	// SigningKeyring holds signing keys
	SigningKeyring struct {
		keys map[string]SigningKey
	}
)

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

type (
	// SigningKeyConstructor constructs a new signing key from params
	SigningKeyConstructor = func(params string) (SigningKey, error)

	// SigningKeyAlgs are a map of valid signing keys
	SigningKeyAlgs interface {
		Get(id string) (SigningKeyConstructor, bool)
	}

	signingKeysMap map[string]SigningKeyConstructor
)

// Signing key algorithms
const (
	SigningAlgHS512 = "hs512"
	SigningAlgRS256 = "rs256"
)

var (
	// DefaultSigningKeyAlgs are the default supported signing key algs
	DefaultSigningKeyAlgs = signingKeysMap{
		SigningAlgHS512: HS512FromParams,
		SigningAlgRS256: RS256FromParams,
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

func signingKeyID(params string) string {
	k := blake2b.Sum256([]byte(params))
	return base64.RawURLEncoding.EncodeToString(k[:])
}
