package h2streamhash

import (
	"crypto/hmac"
	"encoding/base64"
	"hash"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/kerrors"
)

type (
	mockHash struct {
		h hash.Hash
	}
)

func (m *mockHash) Write(src []byte) (int, error) {
	return m.h.Write(src)
}

func (m *mockHash) Close() error {
	_, err := io.WriteString(m.h, "done")
	return err
}

func (m *mockHash) Sum() string {
	var b strings.Builder
	b.WriteString("$test$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(m.h.Sum(nil)))
	return b.String()
}

func (m *mockHash) Verify(checksum string) (bool, error) {
	if !strings.HasPrefix(checksum, "$") {
		return false, kerrors.WithKind(nil, ErrorInvalidFormat, "Invalid test hash format")
	}
	b := strings.Split(strings.TrimPrefix(checksum, "$"), "$")
	if len(b) != 2 || b[0] != "test" {
		return false, kerrors.WithKind(nil, ErrorInvalidFormat, "Invalid test hash format")
	}
	hashval, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return false, kerrors.WithKind(err, ErrorInvalidFormat, "Invalid hash val")
	}
	return hmac.Equal(m.h.Sum(nil), hashval), nil
}

type (
	// mockHasher implements a mock test Hasher
	mockHasher struct{}
)

func (h *mockHasher) ID() string {
	return "test"
}

func (h *mockHasher) Hash() (Hash, error) {
	bh, err := blake2b.New512(nil)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to create hash")
	}
	return &mockHash{
		h: bh,
	}, nil
}

func (h *mockHasher) Verify(checksum string) (Hash, error) {
	return h.Hash()
}

type (
	mockBuilder struct{}
)

func (b mockBuilder) ID() string {
	return "test"
}

func (b mockBuilder) Build(params string) (Hasher, error) {
	if params != "$test$" {
		return nil, kerrors.WithKind(nil, ErrorKeyInvalid, "Invalid key")
	}
	return &mockHasher{}, nil
}

func TestVerifier(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	testAlgs := NewAlgsMap()
	testAlgs.Register(mockBuilder{})

	verifier := NewVerifier()
	hasher, err := FromParams("$test$", testAlgs)
	assert.NoError(err)
	verifier.Register(hasher)

	// success case
	hash, err := hasher.Hash()
	assert.NoError(err)
	_, err = io.WriteString(hash, "password")
	assert.NoError(err)
	assert.NoError(hash.Close())
	checksum := hash.Sum()
	vhash, err := verifier.Verify(checksum)
	assert.NoError(err)
	_, err = io.WriteString(vhash, "password")
	assert.NoError(err)
	assert.NoError(vhash.Close())
	ok, err := vhash.Verify(checksum)
	assert.NoError(err)
	assert.True(ok)
	// invalid msg
	vhash, err = verifier.Verify(checksum)
	assert.NoError(err)
	_, err = io.WriteString(vhash, "different")
	assert.NoError(err)
	assert.NoError(vhash.Close())
	ok, err = vhash.Verify(checksum)
	assert.NoError(err)
	assert.False(ok)

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
			Err:    ErrorNotSupported,
			String: "Hash not supported",
		},
		{
			Err:    ErrorInvalidFormat,
			String: "Invalid checksum format",
		},
		{
			Err:    ErrorClosed,
			String: "Hash closed",
		},
		{
			Err:    ErrorKeyInvalid,
			String: "Invalid hash key",
		},
	} {
		assert.Equal(tc.String, tc.Err.Error())
	}
}
