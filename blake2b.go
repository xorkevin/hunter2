package hunter2

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/blake2b"
)

type (
	Blake2bHasher struct {
		hashid string
	}
)

func NewBlake2bHasher() *Blake2bHasher {
	return &Blake2bHasher{
		hashid: "b2b",
	}
}

func (h *Blake2bHasher) ID() string {
	return h.hashid
}

func (h *Blake2bHasher) exec(key string) []byte {
	k := blake2b.Sum512([]byte(key))
	return k[:]
}

func (h *Blake2bHasher) Hash(key string) (string, error) {
	hash := h.exec(key)

	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(h.hashid)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(hash))
	return b.String(), nil
}

func (h *Blake2bHasher) Verify(key string, hash string) (bool, error) {
	b := strings.Split(strings.TrimLeft(hash, "$"), "$")
	if len(b) != 2 || b[0] != h.hashid {
		return false, errors.New("Invalid blake2b hash format")
	}

	hashval, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return false, err
	}
	res := h.exec(key)
	return hmac.Equal(res, hashval), nil
}
