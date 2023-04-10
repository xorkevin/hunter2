package chacha20

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
	"xorkevin.dev/hunter2/h2streamcipher"
	"xorkevin.dev/kerrors"
)

const (
	CipherID = "xc20"
	MACID    = "p1305"
)

type (
	// Config are xchacha20 params
	Config struct {
		Key   []byte
		Nonce []byte
	}
)

// NewConfig creates a new xchacha20 config
func NewConfig() (*Config, error) {
	key := make([]byte, chacha20.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate xchacha20 key")
	}
	nonce := make([]byte, chacha20.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate xchacha20 nonce")
	}
	return &Config{
		Key:   key,
		Nonce: nonce,
	}, nil
}

// String returns a xchacha20 config as a string
func (c Config) String() string {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(CipherID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Key))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Nonce))
	return b.String()
}

// ParseConfig loads a xchacha20 config from params string
func ParseConfig(params string) (*Config, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2streamcipher.ErrKeyInvalid, "Invalid xchacha20 key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 3 || b[0] != CipherID {
		return nil, kerrors.WithKind(nil, h2streamcipher.ErrKeyInvalid, "Invalid xchacha20 key")
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2streamcipher.ErrKeyInvalid, "Invalid xchacha20 key")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return nil, kerrors.WithKind(err, h2streamcipher.ErrKeyInvalid, "Invalid xchacha20 nonce")
	}
	return &Config{
		Key:   key,
		Nonce: nonce,
	}, nil
}

type (
	// Poly1305Auth computes a poly1305 auth tag
	Poly1305Auth struct {
		closed bool
		mac    *poly1305.MAC
		count  uint64
	}
)

// Write implements [io.Writer]
func (a *Poly1305Auth) Write(src []byte) (int, error) {
	if a.closed {
		return 0, h2streamcipher.ErrClosed
	}
	n, err := a.mac.Write(src)
	if err != nil {
		// should not happen as specified by [hash.Hash]
		return n, kerrors.WithMsg(err, "Failed writing to MAC")
	}
	if n != len(src) && err == nil {
		// should never happen
		return n, kerrors.WithMsg(io.ErrShortWrite, "Short write")
	}
	a.count += uint64(n)
	return n, nil
}

// Close writes the number of bytes of the input to the hash and should be
// called after writing all the input. This prevents length extension attacks.
func (a *Poly1305Auth) Close() error {
	if a.closed {
		return nil
	}

	// taken from golang.org/x/crypto/chacha20poly1305
	if n := a.count % 16; n != 0 {
		// pad length to 16 bytes
		var buf [16]byte
		l := 16 - n
		if k, err := a.mac.Write(buf[:l]); err != nil {
			// should not happen as specified by [hash.Hash]
			return kerrors.WithMsg(err, "Failed writing to MAC")
		} else if k != int(l) {
			// should never happen
			return kerrors.WithMsg(io.ErrShortWrite, "Short write")
		}
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], a.count)
	if n, err := a.mac.Write(buf[:]); err != nil {
		// should not happen as specified by [hash.Hash]
		return kerrors.WithMsg(err, "Failed to write auth count")
	} else if n != 8 {
		// should never happen
		return kerrors.WithMsg(io.ErrShortWrite, "Short write")
	}
	a.closed = true
	return nil
}

// Tag returns an auth tag
func (a *Poly1305Auth) Tag() string {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(MACID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(a.mac.Sum(nil)))
	return b.String()
}

// Verify authenticates ciphertext with an auth tag
func (a *Poly1305Auth) Verify(tagstr string) (bool, error) {
	tag, err := ParsePoly1305Tag(tagstr)
	if err != nil {
		return false, err
	}
	return a.mac.Verify(tag), nil
}

// ParsePoly1305Tag loads a poly1305 tag from string
func ParsePoly1305Tag(tagstr string) ([]byte, error) {
	if !strings.HasPrefix(tagstr, "$") {
		return nil, kerrors.WithKind(nil, h2streamcipher.ErrAuthInvalid, "Invalid poly1305 auth tag format")
	}
	b := strings.Split(strings.TrimPrefix(tagstr, "$"), "$")
	if len(b) != 2 || b[0] != MACID {
		return nil, kerrors.WithKind(nil, h2streamcipher.ErrAuthInvalid, "Invalid poly1305 auth tag format")
	}
	tag, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2streamcipher.ErrAuthInvalid, "Invalid poly1305 auth tag")
	}
	return tag, nil
}

// NewFromConfig creates a xchacha20-poly1305 cipher from config
func NewFromConfig(config Config) (h2streamcipher.KeyStream, *Poly1305Auth, error) {
	s, err := chacha20.NewUnauthenticatedCipher(config.Key, config.Nonce)
	if err != nil {
		return nil, nil, kerrors.WithMsg(err, "Failed to create xchacha20 cipher stream")
	}

	// taken from golang.org/x/crypto/chacha20poly1305
	var polyKey [32]byte
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.SetCounter(1) // set the counter to 1, skipping 32 bytes

	auth := &Poly1305Auth{
		closed: false,
		mac:    poly1305.New(&polyKey),
		count:  0,
	}

	return s, auth, nil
}

// NewFromParams creates a xchacha20-poly1305 cipher from params
func NewFromParams(params string) (h2streamcipher.KeyStream, *Poly1305Auth, error) {
	config, err := ParseConfig(params)
	if err != nil {
		return nil, nil, err
	}
	return NewFromConfig(*config)
}

type (
	builder struct{}
)

func (b builder) ID() string {
	return CipherID
}

func (b builder) Build(params string) (h2streamcipher.KeyStream, h2streamcipher.MAC, error) {
	return NewFromParams(params)
}

// Register registers a cipher alg
func Register(algs h2streamcipher.Algs) {
	algs.Register(builder{})
}
