package h2hash

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/kerrors"
)

var (
	// ErrorNotSupported is returned when the hash is unsupported
	ErrorNotSupported errorNotSupported
	// ErrorInvalidFormat is returned when the hash format is invalid
	ErrorInvalidFormat errorInvalidFormat
	// ErrorKeyInvalid is returned when the hash key config is invalid
	ErrorKeyInvalid errorKeyInvalid
)

type (
	errorNotSupported  struct{}
	errorInvalidFormat struct{}
	errorKeyInvalid    struct{}
)

func (e errorNotSupported) Error() string {
	return "Hash not supported"
}

func (e errorInvalidFormat) Error() string {
	return "Invalid hash format"
}

func (e errorKeyInvalid) Error() string {
	return "Invalid hash key"
}

type (
	// Hasher is a hash interface
	Hasher interface {
		ID() string
		Hash(msg []byte) (string, error)
		Verify(msg []byte, msghash string) (bool, error)
	}

	// Verifier verifies hashes
	Verifier interface {
		Register(hasher Hasher)
		Verify(msg []byte, msghash string) (bool, error)
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
func (v *VerifierMap) Verify(msg []byte, msghash string) (bool, error) {
	if !strings.HasPrefix(msghash, "$") {
		return false, kerrors.WithKind(nil, ErrorInvalidFormat, "Invalid hash format")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(msghash, "$"), "$")
	hasher, ok := v.hashers[id]
	if !ok {
		return false, kerrors.WithKind(nil, ErrorNotSupported, fmt.Sprintf("Hash not registered: %s", id))
	}
	ok, err := hasher.Verify(msg, msghash)
	if err != nil {
		return false, kerrors.WithKind(err, ErrorInvalidFormat, "Failed to verify hash")
	}
	return ok, nil
}

type (
	// Builder constructs a new hasher from params
	Builder interface {
		ID() string
		Build(params string) (Hasher, error)
	}

	// Algs are a map of valid hash algorithms
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

// FromParams creates a hasher from params
func FromParams(params string, algs Algs) (Hasher, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, ErrorKeyInvalid, "Invalid hash key")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	a, ok := algs.Get(id)
	if !ok {
		return nil, kerrors.WithKind(nil, ErrorNotSupported, fmt.Sprintf("Hash not registered: %s", id))
	}
	h, err := a.Build(params)
	if err != nil {
		return nil, kerrors.WithKind(err, ErrorKeyInvalid, "Invalid hash key")
	}
	return h, nil
}

// KeyID computes a key id from params
func KeyID(params string) string {
	k := blake2b.Sum256([]byte(params))
	return base64.RawURLEncoding.EncodeToString(k[:])
}
