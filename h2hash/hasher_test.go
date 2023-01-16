package h2hash

import (
	"crypto/hmac"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/kerrors"
)

type (
	// mockHash implements a mock test Hasher
	mockHash struct{}
)

func (h *mockHash) ID() string {
	return "test"
}

func (h *mockHash) Hash(msg string) (string, error) {
	k := blake2b.Sum512([]byte(msg))
	b := strings.Builder{}
	b.WriteString("$test$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(k[:]))
	return b.String(), nil
}

func (h *mockHash) Verify(msg string, msghash string) (bool, error) {
	if !strings.HasPrefix(msghash, "$") {
		return false, kerrors.WithKind(nil, ErrorInvalidFormat, "Invalid test hash format")
	}
	b := strings.Split(strings.TrimPrefix(msghash, "$"), "$")
	if len(b) != 2 || b[0] != "test" {
		return false, kerrors.WithKind(nil, ErrorInvalidFormat, "Invalid test hash format")
	}
	hashval, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return false, kerrors.WithKind(err, ErrorParamInvalid, "Invalid hash val")
	}
	k := blake2b.Sum512([]byte(msg))
	return hmac.Equal(k[:], hashval), nil
}

func TestVerifier(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	msg := "password"
	hasher := &mockHash{}

	{
		v := NewVerifier()
		v.Register(hasher)

		// success case
		msghash, err := hasher.Hash(msg)
		assert.NoError(err, "hash should be successful")

		ok, err := v.Verify(msg, msghash)
		assert.True(ok, "msg should be correct")
		assert.NoError(err, "msg should be correct")

		// invalid hashid
		ok, err = v.Verify(msg, "$bogusid")
		assert.False(ok, "bogus hashid should fail")
		assert.Error(err, "bogus hashid should fail")
	}
	{
		v := NewVerifier()
		v.Register(hasher)

		// success case
		msghash, err := hasher.Hash(msg)
		assert.NoError(err, "hash should be successful")

		ok, err := v.Verify(msg, msghash)
		assert.True(ok, "msg should be correct")
		assert.NoError(err, "msg should be correct")

		// invalid hashid
		ok, err = v.Verify(msg, "$bogusid")
		assert.False(ok, "bogus hashid should fail")
		assert.Error(err, "bogus hashid should fail")
	}
}
