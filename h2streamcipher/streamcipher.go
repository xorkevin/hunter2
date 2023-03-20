package h2streamcipher

import (
	"fmt"
	"io"
	"strings"

	"xorkevin.dev/kerrors"
)

var (
	// ErrorNotSupported is returned when the cipher is not supported
	ErrorNotSupported errorNotSupported
	// ErrorClosed is returned when writing after the cipher is closed
	ErrorClosed errorClosed
	// ErrorNotClosed is returned when performing computations prior to closing
	ErrorNotClosed errorNotClosed
	// ErrorKeyInvalid is returned when the cipher key config is invalid
	ErrorKeyInvalid errorKeyInvalid
	// ErrorAuthInvalid is returned when the cipher auth tag is invalid
	ErrorAuthInvalid errorAuthInvalid
)

type (
	errorNotSupported struct{}
	errorClosed       struct{}
	errorNotClosed    struct{}
	errorKeyInvalid   struct{}
	errorAuthInvalid  struct{}
)

func (e errorNotSupported) Error() string {
	return "Cipher not supported"
}

func (e errorClosed) Error() string {
	return "Cipher closed"
}

func (e errorNotClosed) Error() string {
	return "Cipher not closed"
}

func (e errorKeyInvalid) Error() string {
	return "Invalid cipher key"
}

func (e errorAuthInvalid) Error() string {
	return "Invalid auth tag"
}

type (
	KeyStream interface {
		XORKeyStream(dst, src []byte)
	}

	MAC interface {
		io.WriteCloser
		Tag() string
		Verify(tag string) (bool, error)
	}
)

type (
	EncStreamReader struct {
		Stream    KeyStream
		MAC       MAC
		Plaintext io.Reader
	}
)

func NewEncStreamReader(s KeyStream, mac MAC, plaintext io.Reader) *EncStreamReader {
	return &EncStreamReader{
		Stream:    s,
		MAC:       mac,
		Plaintext: plaintext,
	}
}

func (r *EncStreamReader) Read(dst []byte) (int, error) {
	n, err := r.Plaintext.Read(dst)
	if n > 0 {
		dstSlice := dst[:n]
		r.Stream.XORKeyStream(dstSlice, dstSlice)
		k, err := r.MAC.Write(dst[:n])
		if err != nil {
			// should not happen as specified by [hash.Hash]
			return n, kerrors.WithMsg(err, "Failed to write to MAC")
		}
		if k != n && err == nil {
			// should never happen
			return n, kerrors.WithMsg(io.ErrShortWrite, "Short write")
		}
	}
	return n, err
}

func (r *EncStreamReader) Close() error {
	if err := r.MAC.Close(); err != nil {
		return kerrors.WithMsg(err, "Failed closing MAC")
	}
	return nil
}

func (r *EncStreamReader) Tag() string {
	return r.MAC.Tag()
}

type (
	DecStreamReader struct {
		closed     bool
		Stream     KeyStream
		MAC        MAC
		Ciphertext io.Reader
	}
)

func NewDecStreamReader(s KeyStream, mac MAC, ciphertext io.Reader) *DecStreamReader {
	return &DecStreamReader{
		closed:     false,
		Stream:     s,
		MAC:        mac,
		Ciphertext: ciphertext,
	}
}

func (r *DecStreamReader) Read(dst []byte) (int, error) {
	n, err := r.Ciphertext.Read(dst)
	if n > 0 {
		k, err := r.MAC.Write(dst[:n])
		if err != nil {
			// should not happen as specified by [hash.Hash]
			return n, kerrors.WithMsg(err, "Failed to write to MAC")
		}
		if k != n && err == nil {
			// should never happen
			return n, kerrors.WithMsg(io.ErrShortWrite, "Short write")
		}
		dstSlice := dst[:n]
		r.Stream.XORKeyStream(dstSlice, dstSlice)
	}
	return n, err
}

func (r *DecStreamReader) Close() error {
	if err := r.MAC.Close(); err != nil {
		return kerrors.WithMsg(err, "Failed closing MAC")
	}
	r.closed = true
	return nil
}

func (r *DecStreamReader) Verify(tag string) (bool, error) {
	if !r.closed {
		return false, kerrors.WithKind(nil, ErrorNotClosed, "Cipher not closed")
	}
	ok, err := r.MAC.Verify(tag)
	if err != nil {
		return false, kerrors.WithKind(nil, ErrorAuthInvalid, "Invalid auth tag")
	}
	return ok, nil
}

type (
	// Builder constructs a new cipher from params
	Builder interface {
		ID() string
		Build(params string) (KeyStream, MAC, error)
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
func FromParams(params string, algs Algs) (KeyStream, MAC, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, nil, kerrors.WithKind(nil, ErrorKeyInvalid, "Invalid cipher key")
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(params, "$"), "$")
	a, ok := algs.Get(id)
	if !ok {
		return nil, nil, kerrors.WithKind(nil, ErrorNotSupported, fmt.Sprintf("Cipher not registered: %s", id))
	}
	s, mac, err := a.Build(params)
	if err != nil {
		return nil, nil, kerrors.WithKind(err, ErrorKeyInvalid, "Invalid cipher key")
	}
	return s, mac, nil
}

// NewDecStreamReaderFromParams creates a dec stream reader from params
func NewDecStreamReaderFromParams(params string, algs Algs, ciphertext io.Reader) (*DecStreamReader, error) {
	s, mac, err := FromParams(params, algs)
	if err != nil {
		return nil, err
	}
	return NewDecStreamReader(s, mac, ciphertext), nil
}
