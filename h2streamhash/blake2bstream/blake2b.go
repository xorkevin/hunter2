package blake2bstream

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/hunter2/h2streamhash"
	"xorkevin.dev/kerrors"
)

const (
	HashID = "b2b"
)

type (
	Config struct {
		Key []byte
	}
)

func NewConfig() (*Config, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate blake2b key")
	}
	return &Config{
		Key: key,
	}, nil
}

func (c Config) String() string {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(HashID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Key))
	return b.String()
}

// ParseConfig loads a blake2b key config from params string
func ParseConfig(params string) (*Config, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2streamhash.ErrKeyInvalid, "Invalid blake2b key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != HashID {
		return nil, kerrors.WithKind(nil, h2streamhash.ErrKeyInvalid, "Invalid blake2b key")
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2streamhash.ErrKeyInvalid, "Invalid blake2b key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Hash implements [h2streamhash.Hash] for blake2b
	Hash struct {
		kid  string
		hash hash.Hash
	}
)

// NewHash creates a new blake2b stream hash
func NewHash(config Config) (*Hash, error) {
	h, err := blake2b.New512(config.Key)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to create blake2b hash")
	}
	kid := ""
	if len(config.Key) != 0 {
		kid = h2streamhash.KeyID(config.String())
	}
	return &Hash{
		kid:  kid,
		hash: h,
	}, nil
}

func (h *Hash) ID() string {
	if h.kid != "" {
		return h.kid
	}
	return HashID
}

// Write implements [io.Writer]
func (h *Hash) Write(src []byte) (int, error) {
	n, err := h.hash.Write(src)
	if err != nil {
		// should not happen as specified by [hash.Hash]
		return n, kerrors.WithMsg(err, "Failed writing to hash")
	}
	if n != len(src) {
		// should never happen
		return n, kerrors.WithMsg(io.ErrShortWrite, "Short write")
	}
	return n, nil
}

// Close implements [h2streamhash.Hash]
func (h *Hash) Close() error {
	return nil
}

// Sum returns a checksum
func (h *Hash) Sum() string {
	var b strings.Builder
	if h.kid != "" {
		b.WriteString("$")
		b.WriteString(h.kid)
	}
	b.WriteString("$")
	b.WriteString(HashID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(h.hash.Sum(nil)))
	return b.String()
}

func (h *Hash) Verify(checksum string) (bool, error) {
	if !strings.HasPrefix(checksum, "$") {
		return false, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid blake2b checksum format")
	}
	b := strings.Split(strings.TrimPrefix(checksum, "$"), "$")
	var hashstr string
	if h.kid != "" {
		if len(b) != 3 || b[0] != h.kid || b[1] != HashID {
			return false, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid blake2b keyed checksum format")
		}
		hashstr = b[2]
	} else {
		if len(b) != 2 || b[0] != HashID {
			return false, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid blake2b checksum format")
		}
		hashstr = b[1]
	}
	hashval, err := base64.RawURLEncoding.DecodeString(hashstr)
	if err != nil {
		return false, kerrors.WithKind(err, h2streamhash.ErrInvalidFormat, "Invalid blake2b checksum format")
	}
	return hmac.Equal(h.hash.Sum(nil), hashval), nil
}

type (
	// Hasher implements [h2streamhash.Hasher] for blake2b
	Hasher struct {
		kid string
		key []byte
	}
)

// New creates a new blake2b hasher
func NewHasher(config Config) *Hasher {
	kid := ""
	if len(config.Key) != 0 {
		kid = h2streamhash.KeyID(config.String())
	}
	return &Hasher{
		kid: kid,
		key: config.Key,
	}
}

// NewHasherFromParams creates a blake2b hasher from params
func NewHasherFromParams(params string) (*Hasher, error) {
	config, err := ParseConfig(params)
	if err != nil {
		return nil, err
	}
	return NewHasher(*config), nil
}

type (
	builder struct{}
)

func (b builder) ID() string {
	return HashID
}

func (b builder) Build(params string) (h2streamhash.Hasher, error) {
	return NewHasherFromParams(params)
}

// Register registers a hash alg
func Register(algs h2streamhash.Algs) {
	algs.Register(builder{})
}

func (h *Hasher) ID() string {
	if h.kid != "" {
		return h.kid
	}
	return HashID
}

func (h *Hasher) Hash() (h2streamhash.Hash, error) {
	return NewHash(Config{
		Key: h.key,
	})
}

func (h *Hasher) Verify(checksum string) (h2streamhash.Hash, error) {
	if !strings.HasPrefix(checksum, "$") {
		return nil, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid blake2b checksum format")
	}
	b := strings.Split(strings.TrimPrefix(checksum, "$"), "$")
	if h.kid != "" {
		if len(b) != 3 || b[0] != h.kid || b[1] != HashID {
			return nil, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid blake2b keyed checksum format")
		}
	} else {
		if len(b) != 2 || b[0] != HashID {
			return nil, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid blake2b checksum format")
		}
	}
	return h.Hash()
}
