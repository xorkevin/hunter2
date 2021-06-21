package hunter2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlake2bHasher(t *testing.T) {
	assert := require.New(t)
	key := "password"

	hasher := NewBlake2bHasher()

	// success case
	hash, err := hasher.Hash(key)
	assert.NoError(err, "hash should be successful")
	ok, err := hasher.Verify(key, hash)
	assert.True(ok, "key should be correct")
	assert.NoError(err, "key should be correct")

	// invalid key
	ok, err = hasher.Verify("notpass", hash)
	assert.False(ok, "incorrect key should fail")
	assert.NoError(err, "incorrect key should not error")

	// invalid hash format
	ok, err = hasher.Verify(key, "")
	assert.False(ok, "blank hash should fail")
	assert.Error(err, "blank hash should fail")
	ok, err = hasher.Verify(key, "$b2b")
	assert.False(ok, "invalid number of hash components should fail")
	assert.Error(err, "invalid number of hash components should fail")

	// invalid hash value
	ok, err = hasher.Verify(key, "$b2b$bogus+hash+val")
	assert.False(ok, "invalid hash should fail")
	assert.Error(err, "invalid hash should fail")
}
