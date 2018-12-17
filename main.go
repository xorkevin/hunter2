package hunter2

import (
	"errors"
	"strings"
)

type (
	// Hasher is a hash interface
	Hasher interface {
		ID() string
		Hash(key string) (string, error)
		Verify(key string, hash string) (bool, error)
	}

	Verifier struct {
		hashers map[string]Hasher
	}
)

func NewVerifier() *Verifier {
	return &Verifier{
		hashers: map[string]Hasher{},
	}
}

func (v *Verifier) RegisterHash(hasher Hasher) {
	v.hashers[hasher.ID()] = hasher
}

// Verify checks to see if the hash of the given key matches the provided keyhash
func (v *Verifier) Verify(key string, hash string) (bool, error) {
	b := strings.SplitN(strings.TrimLeft(hash, "$"), "$", 2)
	hasher, ok := v.hashers[b[0]]
	if !ok {
		return false, errors.New("Hash " + b[0] + " is not registered")
	}
	return hasher.Verify(key, hash)
}
