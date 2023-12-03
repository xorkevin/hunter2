package sha256stream

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"strings"

	"xorkevin.dev/hunter2/h2streamhash"
	"xorkevin.dev/kerrors"
)

const (
	HashID = "sha256"
)

type (
	Config struct {
		Key []byte
	}
)

func NewConfig() (*Config, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate sha256 key")
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

// ParseConfig loads a sha256 key config from params string
func ParseConfig(params string) (*Config, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2streamhash.ErrKeyInvalid, "Invalid sha256 key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != HashID {
		return nil, kerrors.WithKind(nil, h2streamhash.ErrKeyInvalid, "Invalid sha256 key")
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2streamhash.ErrKeyInvalid, "Invalid sha256 key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Hash implements [h2streamhash.Hash] for sha256
	Hash struct {
		kid  string
		hash hash.Hash
	}
)

// NewHash creates a new sha256 stream hash
func NewHash(config Config) *Hash {
	var h hash.Hash
	kid := ""
	if len(config.Key) != 0 {
		h = hmac.New(sha256.New, config.Key)
		kid = h2streamhash.KeyID(config.String())
	} else {
		h = sha256.New()
	}
	return &Hash{
		kid:  kid,
		hash: h,
	}
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
		return false, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid sha256 checksum format")
	}
	b := strings.Split(strings.TrimPrefix(checksum, "$"), "$")
	var hashstr string
	if h.kid != "" {
		if len(b) != 3 || b[0] != h.kid || b[1] != HashID {
			return false, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid sha256 hmac checksum format")
		}
		hashstr = b[2]
	} else {
		if len(b) != 2 || b[0] != HashID {
			return false, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid sha256 checksum format")
		}
		hashstr = b[1]
	}
	hashval, err := base64.RawURLEncoding.DecodeString(hashstr)
	if err != nil {
		return false, kerrors.WithKind(err, h2streamhash.ErrInvalidFormat, "Invalid sha256 checksum format")
	}
	return hmac.Equal(h.hash.Sum(nil), hashval), nil
}

type (
	// Hasher implements [h2streamhash.Hasher] for sha256
	Hasher struct {
		kid string
		key []byte
	}
)

// New creates a new sha256 hasher
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

// NewHasherFromParams creates a sha256 hasher from params
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
	}), nil
}

func (h *Hasher) Verify(checksum string) (h2streamhash.Hash, error) {
	if !strings.HasPrefix(checksum, "$") {
		return nil, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid sha256 checksum format")
	}
	b := strings.Split(strings.TrimPrefix(checksum, "$"), "$")
	if h.kid != "" {
		if len(b) != 3 || b[0] != h.kid || b[1] != HashID {
			return nil, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid sha256 hmac checksum format")
		}
	} else {
		if len(b) != 2 || b[0] != HashID {
			return nil, kerrors.WithKind(nil, h2streamhash.ErrInvalidFormat, "Invalid sha256 checksum format")
		}
	}
	return h.Hash()
}
