package hunter2

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

type (
	ScryptConfig struct {
		workFactor     int
		memBlocksize   int
		parallelFactor int
	}
)

func (c *ScryptConfig) String() string {
	return strings.Join([]string{
		strconv.Itoa(c.workFactor),
		strconv.Itoa(c.memBlocksize),
		strconv.Itoa(c.parallelFactor),
	}, ",")
}

func (c *ScryptConfig) decodeParams(params string) error {
	p := strings.Split(params, ",")
	if len(p) != 3 {
		return errors.New("Invalid number of params")
	}
	wf, err := strconv.Atoi(p[0])
	if err != nil {
		return errors.New("Invalid work factor")
	}
	mb, err := strconv.Atoi(p[1])
	if err != nil {
		return errors.New("Invalid mem blocksize")
	}
	pf, err := strconv.Atoi(p[2])
	if err != nil {
		return errors.New("Invalid parallel factor")
	}
	c.workFactor = wf
	c.memBlocksize = mb
	c.parallelFactor = pf
	return nil
}

func NewScryptConfig(workFactor, memBlocksize, parallelFactor int) ScryptConfig {
	return ScryptConfig{
		workFactor:     workFactor,
		memBlocksize:   memBlocksize,
		parallelFactor: parallelFactor,
	}
}

func NewScryptDefaultConfig() ScryptConfig {
	// 2016
	// attack 0.17s, 64MB
	// user 0.32s
	return NewScryptConfig(65536, 8, 1)
}

type (
	ScryptHasher struct {
		hashid  string
		hashlen int
		saltlen int
		config  ScryptConfig
	}
)

func NewScryptHasher(hashlen, saltlen int, config ScryptConfig) *ScryptHasher {
	return &ScryptHasher{
		hashid:  "s0",
		hashlen: hashlen,
		saltlen: saltlen,
		config:  config,
	}
}

func (h *ScryptHasher) ID() string {
	return h.hashid
}

func (h *ScryptHasher) exec(key string, salt []byte, hashLength int, c ScryptConfig) ([]byte, error) {
	return scrypt.Key([]byte(key), salt, c.workFactor, c.memBlocksize, c.parallelFactor, hashLength)
}

func (h *ScryptHasher) Hash(key string) (string, error) {
	salt := make([]byte, h.saltlen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash, err := h.exec(key, salt, h.hashlen, h.config)
	if err != nil {
		return "", err
	}

	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(h.hashid)
	b.WriteString("$")
	b.WriteString(h.config.String())
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(salt))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(hash))
	return b.String(), nil
}

func (h *ScryptHasher) Verify(key string, hash string) (bool, error) {
	b := strings.Split(strings.TrimLeft(hash, "$"), "$")
	if len(b) != 4 || b[0] != h.hashid {
		return false, errors.New("Invalid scrypt hash format")
	}

	config := ScryptConfig{}
	if err := config.decodeParams(b[1]); err != nil {
		return false, err
	}
	salt, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return false, err
	}
	hashval, err := base64.RawURLEncoding.DecodeString(b[3])
	if err != nil {
		return false, err
	}
	res, err := h.exec(key, salt, len(hashval), config)
	if err != nil {
		return false, err
	}
	return hmac.Equal(res, hashval), nil
}
