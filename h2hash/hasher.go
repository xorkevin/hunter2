package h2hash

import (
	"fmt"
	"strings"

	"xorkevin.dev/kerrors"
)

var (
	// ErrorNotSupported is returned when the hash is unsupported
	ErrorNotSupported errorNotSupported
	// ErrorInvalidFormat is returned when the hash format is invalid
	ErrorInvalidFormat errorInvalidFormat
)

type (
	errorNotSupported  struct{}
	errorInvalidFormat struct{}
	errorParamInvalid  struct{}
)

func (e errorNotSupported) Error() string {
	return "Hash not supported"
}

func (e errorInvalidFormat) Error() string {
	return "Invalid hash format"
}

type (
	// Hasher is a hash interface
	Hasher interface {
		ID() string
		Hash(msg string) (string, error)
		Verify(msg string, msghash string) (bool, error)
	}

	// Verifier verifies hashes
	Verifier interface {
		Register(hasher Hasher)
		Verify(msg string, msghash string) (bool, error)
	}

	VerifierMap struct {
		hashers map[string]Hasher
	}
)

func NewVerifierMap() *VerifierMap {
	return &VerifierMap{
		hashers: map[string]Hasher{},
	}
}

// Register registers a Hasher
func (v *VerifierMap) Register(hasher Hasher) {
	v.hashers[hasher.ID()] = hasher
}

// Verify checks to see if the hash of the given msg matches the provided msghash
func (v *VerifierMap) Verify(msg string, msghash string) (bool, error) {
	if !strings.HasPrefix(msghash, "$") {
		return false, kerrors.WithKind(nil, ErrorInvalidFormat, "Invalid hash format")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(msghash, "$"), "$")
	hasher, ok := v.hashers[id]
	if !ok {
		return false, kerrors.WithKind(nil, ErrorNotSupported, fmt.Sprintf("Hash not registered: %s", id))
	}
	return hasher.Verify(msg, msghash)
}
