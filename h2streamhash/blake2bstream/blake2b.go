package blake2bstream

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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
		return nil, kerrors.WithMsg(err, "Failed to generate aes key")
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
		return nil, kerrors.WithKind(nil, h2streamhash.ErrorKeyInvalid, "Invalid blake2b key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != HashID {
		return nil, kerrors.WithKind(nil, h2streamhash.ErrorKeyInvalid, "Invalid blake2b key")
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2streamhash.ErrorKeyInvalid, "Invalid blake2b key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Hash implements [h2streamhash.Hash] for blake2b
	Hash struct {
		kid    string
		closed bool
		hash   hash.Hash
		count  uint64
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
		kid:    kid,
		closed: false,
		hash:   h,
		count:  0,
	}, nil
}

// Write implements [io.Writer]
func (h *Hash) Write(src []byte) (int, error) {
	if h.closed {
		return 0, h2streamhash.ErrorClosed
	}
	n, err := h.hash.Write(src)
	if err != nil {
		// should not happen as specified by [hash.Hash]
		return n, kerrors.WithMsg(err, "Failed writing to hash")
	}
	if n != len(src) && err == nil {
		// should never happen
		return n, kerrors.WithMsg(io.ErrShortWrite, "Short write")
	}
	h.count += uint64(n)
	return n, nil
}

// Close writes the number of bytes of the input to the hash and should be
// called after writing all the input. This prevents length extension attacks.
func (h *Hash) Close() error {
	if h.closed {
		return nil
	}
	if n := h.count % 16; n > 0 {
		// pad length to 16 bytes
		l := 16 - n
		b := make([]byte, l)
		k, err := h.hash.Write(b)
		if err != nil {
			// should not happen as specified by [hash.Hash]
			return kerrors.WithMsg(err, "Failed writing to hash")
		}
		if k != int(l) && err == nil {
			// should never happen
			return kerrors.WithMsg(io.ErrShortWrite, "Short write")
		}
	}
	if err := binary.Write(h.hash, binary.LittleEndian, h.count); err != nil {
		// should not happen as specified by [hash.Hash]
		return kerrors.WithMsg(err, "Failed to write count")
	}
	h.closed = true
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
		return false, kerrors.WithKind(nil, h2streamhash.ErrorInvalidFormat, "Invalid blake2b checksum format")
	}
	b := strings.Split(strings.TrimPrefix(checksum, "$"), "$")
	var hashstr string
	if h.kid != "" {
		if len(b) != 3 || b[0] != h.kid || b[1] != HashID {
			return false, kerrors.WithKind(nil, h2streamhash.ErrorInvalidFormat, "Invalid blake2b keyed checksum format")
		}
		hashstr = b[2]
	} else {
		if len(b) != 2 || b[0] != HashID {
			return false, kerrors.WithKind(nil, h2streamhash.ErrorInvalidFormat, "Invalid blake2b checksum format")
		}
		hashstr = b[1]
	}
	hashval, err := base64.RawURLEncoding.DecodeString(hashstr)
	if err != nil {
		return false, kerrors.WithKind(err, h2streamhash.ErrorInvalidFormat, "Invalid blake2b checksum format")
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
		return nil, kerrors.WithKind(nil, h2streamhash.ErrorInvalidFormat, "Invalid blake2b checksum format")
	}
	b := strings.Split(strings.TrimPrefix(checksum, "$"), "$")
	if h.kid != "" {
		if len(b) != 3 || b[0] != h.kid || b[1] != HashID {
			return nil, kerrors.WithKind(nil, h2streamhash.ErrorInvalidFormat, "Invalid blake2b keyed checksum format")
		}
	} else {
		if len(b) != 2 || b[0] != HashID {
			return nil, kerrors.WithKind(nil, h2streamhash.ErrorInvalidFormat, "Invalid blake2b checksum format")
		}
	}
	return h.Hash()
}
