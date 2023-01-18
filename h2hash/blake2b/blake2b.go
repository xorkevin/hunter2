package blake2b

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/hunter2/h2cipher"
	"xorkevin.dev/hunter2/h2hash"
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
		return nil, kerrors.WithKind(nil, h2cipher.ErrorKeyInvalid, "Invalid blake2b key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != HashID {
		return nil, kerrors.WithKind(nil, h2cipher.ErrorKeyInvalid, "Invalid blake2b key")
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2cipher.ErrorKeyInvalid, "Invalid blake2b key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Hasher implements [h2hash.Hasher] for blake2b
	Hasher struct {
		kid string
		key []byte
	}
)

// New creates a new blake2b hasher
func New(config Config) *Hasher {
	kid := ""
	if len(config.Key) != 0 {
		kid = h2hash.KeyID(config.String())
	}
	return &Hasher{
		kid: kid,
		key: config.Key,
	}
}

// NewFromParams creates a blake2b hasher from params
func NewFromParams(params string) (*Hasher, error) {
	config, err := ParseConfig(params)
	if err != nil {
		return nil, err
	}
	return New(*config), nil
}

type (
	builder struct{}
)

func (b builder) ID() string {
	return HashID
}

func (b builder) Build(params string) (h2hash.Hasher, error) {
	return NewFromParams(params)
}

// Register registers a cipher alg
func Register(algs h2hash.Algs) {
	algs.Register(builder{})
}

func (h *Hasher) ID() string {
	if h.kid != "" {
		return h.kid
	}
	return HashID
}

func (h *Hasher) exec(msg []byte) ([]byte, error) {
	if len(h.key) == 0 {
		k := blake2b.Sum512(msg)
		return k[:], nil
	}
	bh, err := blake2b.New512(h.key)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to create blake2b hash")
	}
	if _, err := bh.Write(msg); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to compute hash")
	}
	return bh.Sum(nil), nil
}

func (h *Hasher) Hash(msg []byte) (string, error) {
	k, err := h.exec(msg)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	if h.kid != "" {
		b.WriteString("$")
		b.WriteString(h.kid)
	}
	b.WriteString("$")
	b.WriteString(HashID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(k))
	return b.String(), nil
}

func (h *Hasher) Verify(msg []byte, msghash string) (bool, error) {
	if !strings.HasPrefix(msghash, "$") {
		return false, kerrors.WithKind(nil, h2hash.ErrorInvalidFormat, "Invalid blake2b hash format")
	}
	b := strings.Split(strings.TrimPrefix(msghash, "$"), "$")
	var hashstr string
	if h.kid != "" {
		if len(b) != 3 || b[0] != h.kid || b[1] != HashID {
			return false, kerrors.WithKind(nil, h2hash.ErrorInvalidFormat, "Invalid blake2b keyed hash format")
		}
		hashstr = b[2]
	} else {
		if len(b) != 2 || b[0] != HashID {
			return false, kerrors.WithKind(nil, h2hash.ErrorInvalidFormat, "Invalid blake2b hash format")
		}
		hashstr = b[1]
	}

	hashval, err := base64.RawURLEncoding.DecodeString(hashstr)
	if err != nil {
		return false, kerrors.WithKind(err, h2hash.ErrorInvalidFormat, "Invalid hash val")
	}
	res, err := h.exec(msg)
	if err != nil {
		return false, err
	}
	return hmac.Equal(res, hashval), nil
}
