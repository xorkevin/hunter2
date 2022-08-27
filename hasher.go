package hunter2

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrHashNotSupported is returned when the hash is unsupported
	ErrHashNotSupported = errors.New("Hash not supported")
	// ErrHashParamInvalid is returned when the hash param is invalid
	ErrHashParamInvalid = errors.New("Hash invalid param")
)

type (
	// Hasher is a hash interface
	Hasher interface {
		ID() string
		Hash(key string) (string, error)
		Verify(key string, hash string) (bool, error)
	}

	// Verifier verifies hashes
	Verifier struct {
		hashers map[string]Hasher
	}
)

// NewVerifier creates a new verifier
func NewVerifier() *Verifier {
	return &Verifier{
		hashers: map[string]Hasher{},
	}
}

// RegisterHash registers a Hasher
func (v *Verifier) RegisterHash(hasher Hasher) {
	v.hashers[hasher.ID()] = hasher
}

// Verify checks to see if the hash of the given key matches the provided keyhash
func (v *Verifier) Verify(key string, hash string) (bool, error) {
	id, _, _ := strings.Cut(strings.TrimPrefix(hash, "$"), "$")
	hasher, ok := v.hashers[id]
	if !ok {
		return false, fmt.Errorf("%w: %s not registered", ErrHashNotSupported, id)
	}
	return hasher.Verify(key, hash)
}

// Hash IDs
const (
	HashIDScrypt  = "s0"
	HashIDBlake2b = "b2b"
)
