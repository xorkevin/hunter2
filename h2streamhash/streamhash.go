package h2streamhash

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/kerrors"
)

var (
	// ErrorNotSupported is returned when the hash is unsupported
	ErrorNotSupported errorNotSupported
	// ErrorInvalidFormat is returned when the checksum format is invalid
	ErrorInvalidFormat errorInvalidFormat
	// ErrorClosed is returned when writing after the hash is closed
	ErrorClosed errorClosed
	// ErrorNotClosed is returned when performing computations prior to closing
	ErrorNotClosed errorNotClosed
	// ErrorKeyInvalid is returned when the hash key config is invalid
	ErrorKeyInvalid errorKeyInvalid
)

type (
	errorNotSupported  struct{}
	errorInvalidFormat struct{}
	errorClosed        struct{}
	errorNotClosed     struct{}
	errorKeyInvalid    struct{}
)

func (e errorNotSupported) Error() string {
	return "Hash not supported"
}

func (e errorInvalidFormat) Error() string {
	return "Invalid checksum format"
}

func (e errorClosed) Error() string {
	return "Hash closed"
}

func (e errorNotClosed) Error() string {
	return "Hash not closed"
}

func (e errorKeyInvalid) Error() string {
	return "Invalid hash key"
}

type (
	Hash interface {
		io.WriteCloser
		Sum() string
		Verify(checksum string) (bool, error)
	}

	// Hasher creates a [Hash]
	Hasher interface {
		ID() string
		Hash() (Hash, error)
		Verify(checksum string) (Hash, error)
	}

	// Verifier verifies hashes
	Verifier struct {
		hashers map[string]Hasher
	}
)

func NewVerifier() *Verifier {
	return &Verifier{
		hashers: map[string]Hasher{},
	}
}

// Register registers a Hasher
func (v *Verifier) Register(hasher Hasher) {
	v.hashers[hasher.ID()] = hasher
}

// Verify returns the hash to verify a checksum
func (v *Verifier) Verify(checksum string) (Hash, error) {
	if !strings.HasPrefix(checksum, "$") {
		return nil, kerrors.WithKind(nil, ErrorInvalidFormat, "Invalid checksum format")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(checksum, "$"), "$")
	hasher, ok := v.hashers[id]
	if !ok {
		return nil, kerrors.WithKind(nil, ErrorNotSupported, fmt.Sprintf("Hash not registered: %s", id))
	}
	h, err := hasher.Verify(checksum)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to construct hash")
	}
	return h, nil
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
