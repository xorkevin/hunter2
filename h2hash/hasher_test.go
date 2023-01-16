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
		return false, kerrors.WithKind(err, ErrorInvalidFormat, "Invalid hash val")
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
		v := NewVerifierMap()
		ok, err := v.Verify("abc", "bogus")
		assert.False(ok)
		assert.ErrorIs(err, ErrorInvalidFormat)
	}

	{
		v := NewVerifierMap()
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
		assert.ErrorIs(err, ErrorNotSupported, "bogus hashid should fail")
	}
	{
		v := NewVerifierMap()
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
		assert.Error(err, ErrorNotSupported, "bogus hashid should fail")
	}
}

func TestError(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	for _, tc := range []struct {
		Err    error
		String string
	}{
		{
			Err:    ErrorNotSupported,
			String: "Hash not supported",
		},
		{
			Err:    ErrorInvalidFormat,
			String: "Invalid hash format",
		},
	} {
		assert.Equal(tc.String, tc.Err.Error())
	}
}
