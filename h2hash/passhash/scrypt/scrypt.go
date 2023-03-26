package scrypt

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
	"xorkevin.dev/hunter2/h2hash"
	"xorkevin.dev/kerrors"
)

const (
	HashID = "s0"
)

type (
	// Config are scrypt params
	//
	// Recommended minimum parameters are:
	//   - WorkFactor: 32768
	//   - MemBlocksize: 8
	//   - ParallelFactor: 1
	Config struct {
		WorkFactor     int
		MemBlocksize   int
		ParallelFactor int
	}
)

func (c *Config) String() string {
	return strings.Join([]string{
		strconv.Itoa(c.WorkFactor),
		strconv.Itoa(c.MemBlocksize),
		strconv.Itoa(c.ParallelFactor),
	}, ",")
}

func (c *Config) decodeParams(params string) error {
	p := strings.Split(params, ",")
	if len(p) != 3 {
		return kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid params format")
	}
	var err error
	c.WorkFactor, err = strconv.Atoi(p[0])
	if err != nil {
		return kerrors.WithKind(err, h2hash.ErrInvalidFormat, "Invalid work factor")
	}
	c.MemBlocksize, err = strconv.Atoi(p[1])
	if err != nil {
		return kerrors.WithKind(err, h2hash.ErrInvalidFormat, "Invalid mem blocksize")
	}
	c.ParallelFactor, err = strconv.Atoi(p[2])
	if err != nil {
		return kerrors.WithKind(err, h2hash.ErrInvalidFormat, "Invalid parallel factor")
	}
	return nil
}

type (
	// Hasher implements [h2hash.Hasher] for scrypt
	Hasher struct {
		hashlen int
		saltlen int
		config  Config
	}
)

// New creates a new scrypt hasher
func New(hashlen, saltlen int, config Config) *Hasher {
	return &Hasher{
		hashlen: hashlen,
		saltlen: saltlen,
		config:  config,
	}
}

func (h *Hasher) ID() string {
	return HashID
}

func (h *Hasher) exec(msg []byte, salt []byte, hashLength int, c Config) ([]byte, error) {
	b, err := scrypt.Key(msg, salt, c.WorkFactor, c.MemBlocksize, c.ParallelFactor, hashLength)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to hash payload")
	}
	return b, nil
}

func (h *Hasher) Hash(msg []byte) (string, error) {
	salt := make([]byte, h.saltlen)
	if _, err := rand.Read(salt); err != nil {
		return "", kerrors.WithMsg(err, "Failed to generate salt")
	}
	msghash, err := h.exec(msg, salt, h.hashlen, h.config)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("$")
	b.WriteString(HashID)
	b.WriteString("$")
	b.WriteString(h.config.String())
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(salt))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(msghash))
	return b.String(), nil
}

func (h *Hasher) Verify(msg []byte, msghash string) (bool, error) {
	if !strings.HasPrefix(msghash, "$") {
		return false, kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid scrypt hash format")
	}
	b := strings.Split(strings.TrimPrefix(msghash, "$"), "$")
	if len(b) != 4 || b[0] != HashID {
		return false, kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid scrypt hash format")
	}

	var config Config
	if err := config.decodeParams(b[1]); err != nil {
		return false, err
	}
	salt, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return false, kerrors.WithKind(err, h2hash.ErrInvalidFormat, "Invalid salt")
	}
	hashval, err := base64.RawURLEncoding.DecodeString(b[3])
	if err != nil {
		return false, kerrors.WithKind(err, h2hash.ErrInvalidFormat, "Invalid hash val")
	}
	res, err := h.exec(msg, salt, len(hashval), config)
	if err != nil {
		return false, err
	}
	return hmac.Equal(res, hashval), nil
}
