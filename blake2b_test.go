package hunter2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBlake2bHasher(t *testing.T) {
	assert := assert.New(t)
	key := "password"

	hasher := NewBlake2bHasher()

	// success case
	hash, err := hasher.Hash(key)
	assert.Nil(err, "hash should be successful")
	ok, err := hasher.Verify(key, hash)
	assert.True(ok, "key should be correct")
	assert.Nil(err, "key should be correct")

	// invalid key
	ok, err = hasher.Verify("notpass", hash)
	assert.False(ok, "incorrect key should fail")
	assert.Nil(err, "incorrect key should not error")

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
