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

func (h *mockHash) Hash(key []byte, msg string) (string, error) {
	var inp []byte
	inp = append(inp, key...)
	inp = append(inp, []byte(msg)...)
	k := blake2b.Sum512(inp)
	b := strings.Builder{}
	b.WriteString("$test$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(k[:]))
	return b.String(), nil
}

func (h *mockHash) Verify(key []byte, msg string, msghash string) (bool, error) {
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
	var inp []byte
	inp = append(inp, key...)
	inp = append(inp, []byte(msg)...)
	k := blake2b.Sum512(inp)
	return hmac.Equal(k[:], hashval), nil
}

func TestVerifier(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	msg := "password"
	hasher := &mockHash{}

	{
		v := NewVerifierMap()
		ok, err := v.Verify(nil, "abc", "bogus")
		assert.ErrorIs(err, ErrorInvalidFormat)
		assert.False(ok)
	}

	{
		v := NewVerifierMap()
		v.Register(hasher)

		// success case
		msghash, err := hasher.Hash(nil, msg)
		assert.NoError(err, "hash should be successful")

		ok, err := v.Verify(nil, msg, msghash)
		assert.NoError(err, "msg should be correct")
		assert.True(ok, "msg should be correct")

		// invalid hashid
		ok, err = v.Verify(nil, msg, "$bogusid")
		assert.ErrorIs(err, ErrorNotSupported, "bogus hashid should fail")
		assert.False(ok, "bogus hashid should fail")

		// invalid params
		ok, err = v.Verify(nil, msg, "$test$$")
		assert.ErrorIs(err, ErrorInvalidFormat)
		assert.False(ok)
	}
	{
		v := NewVerifierMap()
		v.Register(hasher)

		// success case
		msghash, err := hasher.Hash([]byte("key"), msg)
		assert.NoError(err)

		ok, err := v.Verify([]byte("key"), msg, msghash)
		assert.NoError(err)
		assert.True(ok)

		// invalid hashid
		ok, err = v.Verify([]byte("other"), msg, msghash)
		assert.NoError(err)
		assert.False(ok)
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
