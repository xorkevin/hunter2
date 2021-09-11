package hunter2

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

type (
	// ScryptConfig are scrypt params
	ScryptConfig struct {
		WorkFactor     int
		MemBlocksize   int
		ParallelFactor int
	}
)

func (c *ScryptConfig) String() string {
	return strings.Join([]string{
		strconv.Itoa(c.WorkFactor),
		strconv.Itoa(c.MemBlocksize),
		strconv.Itoa(c.ParallelFactor),
	}, ",")
}

func (c *ScryptConfig) decodeParams(params string) error {
	p := strings.Split(params, ",")
	if len(p) != 3 {
		return fmt.Errorf("%w: invalid params format", ErrHashParamInvalid)
	}
	var err error
	c.WorkFactor, err = strconv.Atoi(p[0])
	if err != nil {
		return fmt.Errorf("%w: invalid work factor", ErrHashParamInvalid)
	}
	c.MemBlocksize, err = strconv.Atoi(p[1])
	if err != nil {
		return fmt.Errorf("%w: invalid mem blocksize", ErrHashParamInvalid)
	}
	c.ParallelFactor, err = strconv.Atoi(p[2])
	if err != nil {
		return fmt.Errorf("%w: invalid parallel factor", ErrHashParamInvalid)
	}
	return nil
}

// NewScryptConfig creates a new scrypt config
func NewScryptConfig(workFactor, memBlocksize, parallelFactor int) ScryptConfig {
	return ScryptConfig{
		WorkFactor:     workFactor,
		MemBlocksize:   memBlocksize,
		ParallelFactor: parallelFactor,
	}
}

var (
	// DefaultScryptConfig is the default scrypt config
	DefaultScryptConfig = NewScryptConfig(65536, 8, 1)
)

type (
	// ScryptHasher implements Hasher for scrypt
	ScryptHasher struct {
		hashlen int
		saltlen int
		config  ScryptConfig
	}
)

// NewScryptHasher creates a new scrypt hasher
func NewScryptHasher(hashlen, saltlen int, config ScryptConfig) Hasher {
	return &ScryptHasher{
		hashlen: hashlen,
		saltlen: saltlen,
		config:  config,
	}
}

func (h *ScryptHasher) ID() string {
	return HashIDScrypt
}

func (h *ScryptHasher) exec(key string, salt []byte, hashLength int, c ScryptConfig) ([]byte, error) {
	return scrypt.Key([]byte(key), salt, c.WorkFactor, c.MemBlocksize, c.ParallelFactor, hashLength)
}

func (h *ScryptHasher) Hash(key string) (string, error) {
	salt := make([]byte, h.saltlen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("Failed to generate salt: %w", err)
	}
	hash, err := h.exec(key, salt, h.hashlen, h.config)
	if err != nil {
		return "", fmt.Errorf("Failed to hash payload: %w", err)
	}

	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(HashIDScrypt)
	b.WriteString("$")
	b.WriteString(h.config.String())
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(salt))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(hash))
	return b.String(), nil
}

func (h *ScryptHasher) Verify(key string, hash string) (bool, error) {
	b := strings.Split(strings.TrimPrefix(hash, "$"), "$")
	if len(b) != 4 || b[0] != HashIDScrypt {
		return false, fmt.Errorf("%w: invalid scrypt hash format", ErrHashParamInvalid)
	}

	config := ScryptConfig{}
	if err := config.decodeParams(b[1]); err != nil {
		return false, err
	}
	salt, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return false, fmt.Errorf("Invalid salt: %w", err)
	}
	hashval, err := base64.RawURLEncoding.DecodeString(b[3])
	if err != nil {
		return false, fmt.Errorf("Invalid hash val: %w", err)
	}
	res, err := h.exec(key, salt, len(hashval), config)
	if err != nil {
		return false, fmt.Errorf("Failed to hash payload: %w", err)
	}
	return hmac.Equal(res, hashval), nil
}
