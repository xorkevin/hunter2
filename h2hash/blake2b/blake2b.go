package blake2b

import (
	"crypto/hmac"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/hunter2/h2hash"
	"xorkevin.dev/kerrors"
)

const (
	HashID = "b2b"
)

type (
	// Hasher implements [h2hash.Hasher] for blake2b
	Hasher struct{}
)

// New creates a new blake2b hasher
func New() h2hash.Hasher {
	return &Hasher{}
}

func (h *Hasher) ID() string {
	return HashID
}

func (h *Hasher) exec(key string) []byte {
	k := blake2b.Sum512([]byte(key))
	return k[:]
}

func (h *Hasher) Hash(key string) (string, error) {
	k := h.exec(key)

	var b strings.Builder
	b.WriteString("$")
	b.WriteString(HashID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(k))
	return b.String(), nil
}

func (h *Hasher) Verify(msg string, msghash string) (bool, error) {
	if !strings.HasPrefix(msghash, "$") {
		return false, kerrors.WithKind(nil, h2hash.ErrorInvalidFormat, "Invalid blake2b hash format")
	}
	b := strings.Split(strings.TrimPrefix(msghash, "$"), "$")
	if len(b) != 2 || b[0] != HashID {
		return false, kerrors.WithKind(nil, h2hash.ErrorInvalidFormat, "Invalid blake2b hash format")
	}

	hashval, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return false, kerrors.WithKind(err, h2hash.ErrorParamInvalid, "Invalid hash val")
	}
	res := h.exec(msg)
	return hmac.Equal(res, hashval), nil
}
