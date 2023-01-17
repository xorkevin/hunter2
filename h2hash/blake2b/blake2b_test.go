package blake2b

import (
	"testing"

	"github.com/stretchr/testify/require"
	"xorkevin.dev/hunter2/h2hash"
)

func TestHasher(t *testing.T) {
	assert := require.New(t)
	msg := "password"

	hasher := New()

	assert.Equal(HashID, hasher.ID())

	// success case
	hash, err := hasher.Hash(nil, msg)
	assert.NoError(err, "hash should be successful")
	ok, err := hasher.Verify(nil, msg, hash)
	assert.NoError(err, "msg should be correct")
	assert.True(ok, "msg should be correct")

	{
		// invalid msg
		ok, err := hasher.Verify(nil, "notpass", hash)
		assert.NoError(err, "incorrect msg should not error")
		assert.False(ok, "incorrect msg should fail")
	}

	{
		// invalid hash format
		ok, err := hasher.Verify(nil, msg, "")
		assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "blank hash should fail")
		assert.False(ok, "blank hash should fail")
		ok, err = hasher.Verify(nil, msg, "$b2b")
		assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "invalid number of hash components should fail")
		assert.False(ok, "invalid number of hash components should fail")
	}

	{
		// invalid hash value
		ok, err := hasher.Verify(nil, msg, "$b2b$bogus+hash+val")
		assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "invalid hash should fail")
		assert.False(ok, "invalid hash should fail")
	}

	{
		// successful MAC
		hash, err := hasher.Hash([]byte("key"), msg)
		assert.NoError(err)
		ok, err := hasher.Verify([]byte("key"), msg, hash)
		assert.NoError(err)
		assert.True(ok)
		ok, err = hasher.Verify([]byte("other"), msg, hash)
		assert.NoError(err)
		assert.False(ok)
	}
}
