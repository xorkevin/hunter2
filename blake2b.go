package hunter2

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

type (
	// Blake2bHasher implements Hasher for blake2b
	Blake2bHasher struct{}
)

//NewBlake2bHasher creates a new blake2b hasher
func NewBlake2bHasher() Hasher {
	return &Blake2bHasher{}
}

func (h *Blake2bHasher) ID() string {
	return HashIDBlake2b
}

func (h *Blake2bHasher) exec(key string) []byte {
	k := blake2b.Sum512([]byte(key))
	return k[:]
}

func (h *Blake2bHasher) Hash(key string) (string, error) {
	hash := h.exec(key)

	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(HashIDBlake2b)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(hash))
	return b.String(), nil
}

func (h *Blake2bHasher) Verify(key string, hash string) (bool, error) {
	b := strings.Split(strings.TrimLeft(hash, "$"), "$")
	if len(b) != 2 || b[0] != HashIDBlake2b {
		return false, fmt.Errorf("%w: invalid blake2b hash format", ErrHashParamInvalid)
	}

	hashval, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return false, fmt.Errorf("Invalid hash val: %w", err)
	}
	res := h.exec(key)
	return hmac.Equal(res, hashval), nil
}
