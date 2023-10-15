package argon2

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"xorkevin.dev/hunter2/h2hash"
	"xorkevin.dev/kerrors"
)

const (
	HashID  = "a2id"
	Version = argon2.Version
)

type (
	// Config is argon2id params
	Config struct {
		Version  int
		Time     uint32
		Mem      uint32
		Parallel uint8
	}
)

func (c *Config) String() string {
	return strings.Join([]string{
		"v=" + strconv.Itoa(c.Version),
		"m=" + strconv.FormatUint(uint64(c.Mem), 10),
		"t=" + strconv.FormatUint(uint64(c.Time), 10),
		"p=" + strconv.FormatUint(uint64(c.Parallel), 10),
	}, ",")
}

func (c *Config) decodeParams(params string) error {
	a := strings.Split(params, ",")
	if len(a) != 4 {
		return kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid params format")
	}
	vs, ok := strings.CutPrefix(a[0], "v=")
	if !ok {
		return kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid hash version")
	}
	var err error
	c.Version, err = strconv.Atoi(vs)
	if err != nil {
		return kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid hash version")
	}
	ms, ok := strings.CutPrefix(a[1], "m=")
	if !ok {
		return kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid memory cost")
	}
	m, err := strconv.ParseUint(ms, 10, 32)
	if err != nil {
		return kerrors.WithKind(err, h2hash.ErrInvalidFormat, "Invalid memory cost")
	}
	c.Mem = uint32(m)
	ts, ok := strings.CutPrefix(a[2], "t=")
	if !ok {
		return kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid time cost")
	}
	t, err := strconv.ParseUint(ts, 10, 32)
	if err != nil {
		return kerrors.WithKind(err, h2hash.ErrInvalidFormat, "Invalid time cost")
	}
	c.Time = uint32(t)
	ps, ok := strings.CutPrefix(a[3], "p=")
	if !ok {
		return kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid parallel cost")
	}
	p, err := strconv.ParseUint(ps, 10, 8)
	if err != nil {
		return kerrors.WithKind(err, h2hash.ErrInvalidFormat, "Invalid parallel cost")
	}
	c.Parallel = uint8(p)
	return nil
}

type (
	// Hasher implements [h2hash.Hasher] for argon2id
	Hasher struct {
		hashlen int
		saltlen int
		config  Config
	}
)

// New creates a new argon2id hasher
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
	if c.Version != argon2.Version {
		return nil, kerrors.WithKind(nil, h2hash.ErrNotSupported, "Argon2 hash version not supported")
	}
	return argon2.IDKey(msg, salt, c.Time, c.Mem, c.Parallel, uint32(hashLength)), nil
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
	msghash, ok := strings.CutPrefix(msghash, "$")
	if !ok {
		return false, kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid argon2id hash format")
	}
	b := strings.Split(msghash, "$")
	if len(b) != 4 || b[0] != HashID {
		return false, kerrors.WithKind(nil, h2hash.ErrInvalidFormat, "Invalid argon2id hash format")
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
