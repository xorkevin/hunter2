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

func (h *mockHash) Hash(msg []byte) (string, error) {
	k := blake2b.Sum512(msg)
	var b strings.Builder
	b.WriteString("$test$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(k[:]))
	return b.String(), nil
}

func (h *mockHash) Verify(msg []byte, msghash string) (bool, error) {
	if !strings.HasPrefix(msghash, "$") {
		return false, kerrors.WithKind(nil, ErrInvalidFormat, "Invalid test hash format")
	}
	b := strings.Split(strings.TrimPrefix(msghash, "$"), "$")
	if len(b) != 2 || b[0] != "test" {
		return false, kerrors.WithKind(nil, ErrInvalidFormat, "Invalid test hash format")
	}
	hashval, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return false, kerrors.WithKind(err, ErrInvalidFormat, "Invalid hash val")
	}
	k := blake2b.Sum512(msg)
	return hmac.Equal(k[:], hashval), nil
}

type (
	mockBuilder struct{}
)

func (b mockBuilder) ID() string {
	return "test"
}

func (b mockBuilder) Build(params string) (Hasher, error) {
	if params != "$test$" {
		return nil, kerrors.WithKind(nil, ErrKeyInvalid, "Invalid key")
	}
	return &mockHash{}, nil
}

func TestVerifier(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	testAlgs := NewAlgsMap()
	testAlgs.Register(mockBuilder{})

	msg := "password"

	{
		v := NewVerifier()
		ok, err := v.Verify([]byte("abc"), "bogus")
		assert.ErrorIs(err, ErrInvalidFormat)
		assert.False(ok)
	}

	{

		v := NewVerifier()
		hasher, err := FromParams("$test$", testAlgs)
		assert.NoError(err)
		v.Register(hasher)

		// success case
		msghash, err := hasher.Hash([]byte(msg))
		assert.NoError(err, "hash should be successful")

		ok, err := v.Verify([]byte(msg), msghash)
		assert.NoError(err, "msg should be correct")
		assert.True(ok, "msg should be correct")

		// invalid hashid
		ok, err = v.Verify([]byte(msg), "$bogusid")
		assert.ErrorIs(err, ErrNotSupported, "bogus hashid should fail")
		assert.False(ok, "bogus hashid should fail")

		// invalid params
		ok, err = v.Verify([]byte(msg), "$test$$")
		assert.ErrorIs(err, ErrInvalidFormat)
		assert.False(ok)
	}

	assert.NotEqual("", KeyID("abc"))
}

func TestError(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	for _, tc := range []struct {
		Err    error
		String string
	}{
		{
			Err:    ErrNotSupported,
			String: "Hash not supported",
		},
		{
			Err:    ErrInvalidFormat,
			String: "Invalid hash format",
		},
		{
			Err:    ErrKeyInvalid,
			String: "Invalid hash key",
		},
	} {
		assert.Equal(tc.String, tc.Err.Error())
	}
}
