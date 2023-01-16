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
	// ErrorParamInvalid is returned when the hash param is invalid
	ErrorParamInvalid errorParamInvalid
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

func (e errorParamInvalid) Error() string {
	return "Hash invalid param"
}

type (
	// Hasher is a hash interface
	Hasher interface {
		ID() string
		Hash(msg string) (string, error)
		Verify(msg string, msghash string) (bool, error)
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

// Register registers a Hasher
func (v *Verifier) Register(hasher Hasher) {
	v.hashers[hasher.ID()] = hasher
}

// Verify checks to see if the hash of the given msg matches the provided msghash
func (v *Verifier) Verify(msg string, msghash string) (bool, error) {
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
