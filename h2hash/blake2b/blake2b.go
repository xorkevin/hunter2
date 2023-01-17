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
func New() *Hasher {
	return &Hasher{}
}

func (h *Hasher) ID() string {
	return HashID
}

func (h *Hasher) exec(key []byte, msg string) ([]byte, error) {
	if len(key) == 0 {
		k := blake2b.Sum512([]byte(msg))
		return k[:], nil
	}
	bh, err := blake2b.New512(key)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to create blake2b hash")
	}
	if _, err := bh.Write([]byte(msg)); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to compute hash")
	}
	return bh.Sum(nil), nil
}

func (h *Hasher) Hash(key []byte, msg string) (string, error) {
	k, err := h.exec(key, msg)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("$")
	b.WriteString(HashID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(k))
	return b.String(), nil
}

func (h *Hasher) Verify(key []byte, msg string, msghash string) (bool, error) {
	if !strings.HasPrefix(msghash, "$") {
		return false, kerrors.WithKind(nil, h2hash.ErrorInvalidFormat, "Invalid blake2b hash format")
	}
	b := strings.Split(strings.TrimPrefix(msghash, "$"), "$")
	if len(b) != 2 || b[0] != HashID {
		return false, kerrors.WithKind(nil, h2hash.ErrorInvalidFormat, "Invalid blake2b hash format")
	}

	hashval, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return false, kerrors.WithKind(err, h2hash.ErrorInvalidFormat, "Invalid hash val")
	}
	res, err := h.exec(key, msg)
	if err != nil {
		return false, err
	}
	return hmac.Equal(res, hashval), nil
}
