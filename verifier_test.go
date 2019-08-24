package hunter2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifier(t *testing.T) {
	assert := assert.New(t)
	key := "password"

	{
		hasher := NewScryptHasher(16, 16, NewScryptDefaultConfig())

		v := NewVerifier()
		v.RegisterHash(hasher)

		// success case
		hash, err := hasher.Hash(key)
		assert.Nil(err, "hash should be successful")

		ok, err := v.Verify(key, hash)
		assert.True(ok, "key should be correct")
		assert.Nil(err, "key should be correct")

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
		assert.Nil(err, "hash should be successful")

		ok, err := v.Verify(key, hash)
		assert.True(ok, "key should be correct")
		assert.Nil(err, "key should be correct")

		// invalid hashid
		ok, err = v.Verify(key, "$bogusid")
		assert.False(ok, "bogus hashid should fail")
		assert.Error(err, "bogus hashid should fail")
	}
}
