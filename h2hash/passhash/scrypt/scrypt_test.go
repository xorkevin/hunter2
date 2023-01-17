package scrypt

import (
	"testing"

	"github.com/stretchr/testify/require"
	"xorkevin.dev/hunter2/h2hash"
)

func TestHasher(t *testing.T) {
	assert := require.New(t)
	msg := "password"

	hasher := New(16, 16, Config{
		WorkFactor:     64,
		MemBlocksize:   2,
		ParallelFactor: 1,
	})

	assert.Equal(HashID, hasher.ID())

	// success case
	msghash, err := hasher.Hash(nil, msg)
	assert.NoError(err, "hash should be successful")
	ok, err := hasher.Verify(nil, msg, msghash)
	assert.True(ok, "msg should be correct")
	assert.NoError(err, "msg should be correct")

	// invalid msg
	ok, err = hasher.Verify(nil, "notpass", msghash)
	assert.False(ok, "incorrect msg should fail")
	assert.NoError(err, "incorrect msg should not error")

	// invalid hash format
	ok, err = hasher.Verify(nil, msg, "")
	assert.False(ok, "blank hash should fail")
	assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "blank hash should fail")
	ok, err = hasher.Verify(nil, msg, "$s0")
	assert.False(ok, "invalid number of hash components should fail")
	assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "invalid number of hash components should fail")

	// invalid parameters
	ok, err = hasher.Verify(nil, msg, "$s0$$$")
	assert.False(ok, "invalid number of parameters should fail")
	assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "invalid number of parameters should fail")
	ok, err = hasher.Verify(nil, msg, "$s0$,,$$")
	assert.False(ok, "invalid parameters should fail")
	assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "invalid parameters should fail")
	ok, err = hasher.Verify(nil, msg, "$s0$0,,$$")
	assert.False(ok, "invalid parameters should fail")
	assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "invalid parameters should fail")
	ok, err = hasher.Verify(nil, msg, "$s0$0,0,$$")
	assert.False(ok, "invalid parameters should fail")
	assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "invalid parameters should fail")
	ok, err = hasher.Verify(nil, msg, "$s0$0,0,0$$")
	assert.False(ok, "invalid parameters should fail")
	assert.Error(err, "invalid parameters should fail")

	// invalid salt
	ok, err = hasher.Verify(nil, msg, "$s0$0,0,0$bogus+salt+value$")
	assert.False(ok, "invalid salt should fail")
	assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "invalid salt should fail")

	// invalid hash
	ok, err = hasher.Verify(nil, msg, "$s0$0,0,0$bogussaltvalue$bogus+hash+value")
	assert.False(ok, "invalid hash should fail")
	assert.ErrorIs(err, h2hash.ErrorInvalidFormat, "invalid hash should fail")

	// invalid param values
	ok, err = hasher.Verify(nil, msg, "$s0$0,0,0$bogussaltvalue$bogushashvalue")
	assert.False(ok, "invalid parameter values should fail")
	assert.Error(err, "invalid parameter values should fail")

	// invalid config
	invalidHasher := New(0, 0, Config{
		WorkFactor:     0,
		MemBlocksize:   0,
		ParallelFactor: 0,
	})
	msghash, err = invalidHasher.Hash(nil, msg)
	assert.Equal("", msghash, "invalid config should fail")
	assert.Error(err, "invalid config should fail")
}
