package hunter2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifier(t *testing.T) {
	assert := require.New(t)
	key := "password"

	{
		hasher := NewScryptHasher(16, 16, NewScryptDefaultConfig())

		v := NewVerifier()
		v.RegisterHash(hasher)

		// success case
		hash, err := hasher.Hash(key)
		assert.NoError(err, "hash should be successful")

		ok, err := v.Verify(key, hash)
		assert.True(ok, "key should be correct")
		assert.NoError(err, "key should be correct")

		// invalid hashid
		ok, err = v.Verify(key, "$bogusid")
		assert.False(ok, "bogus hashid should fail")
		assert.Error(err, "bogus hashid should fail")
	}
	{
		hasher := NewBlake2bHasher()

		v := NewVerifier()
		v.RegisterHash(hasher)

		// success case
		hash, err := hasher.Hash(key)
		assert.NoError(err, "hash should be successful")

		ok, err := v.Verify(key, hash)
		assert.True(ok, "key should be correct")
		assert.NoError(err, "key should be correct")

		// invalid hashid
		ok, err = v.Verify(key, "$bogusid")
		assert.False(ok, "bogus hashid should fail")
		assert.Error(err, "bogus hashid should fail")
	}
}
