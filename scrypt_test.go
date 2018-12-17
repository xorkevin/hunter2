package hunter2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_ScryptHasher(t *testing.T) {
	assert := assert.New(t)
	key := "password"

	hasher := NewScryptHasher(16, 16, NewScryptDefaultConfig())

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

	// invalid hash
	ok, err = hasher.Verify(key, "")
	assert.False(ok, "blank hash should fail")
	assert.Error(err, "blank hash should fail")
	ok, err = hasher.Verify(key, "$s0")
	assert.False(ok, "invalid number of hash components should fail")
	assert.Error(err, "invalid number of hash components should fail")

	// invalid parameters
	ok, err = hasher.Verify(key, "$s0$$$")
	assert.False(ok, "invalid number of parameters should fail")
	assert.Error(err, "invalid number of parameters should fail")
	ok, err = hasher.Verify(key, "$s0$,,$$")
	assert.False(ok, "invalid parameters should fail")
	assert.Error(err, "invalid parameters should fail")
	ok, err = hasher.Verify(key, "$s0$0,,$$")
	assert.False(ok, "invalid parameters should fail")
	assert.Error(err, "invalid parameters should fail")
	ok, err = hasher.Verify(key, "$s0$0,0,$$")
	assert.False(ok, "invalid parameters should fail")
	assert.Error(err, "invalid parameters should fail")
	ok, err = hasher.Verify(key, "$s0$0,0,0$$")
	assert.False(ok, "invalid parameters should fail")
	assert.Error(err, "invalid parameters should fail")

	// invalid salt
	ok, err = hasher.Verify(key, "$s0$0,0,0$bogus+salt+value$")
	assert.False(ok, "invalid salt should fail")
	assert.Error(err, "invalid salt should fail")

	// invalid hash
	ok, err = hasher.Verify(key, "$s0$0,0,0$bogussaltvalue$bogus+hash+value")
	assert.False(ok, "invalid hash should fail")
	assert.Error(err, "invalid hash should fail")

	// invalid param values
	ok, err = hasher.Verify(key, "$s0$0,0,0$bogussaltvalue$bogushashvalue")
	assert.False(ok, "invalid parameter values should fail")
	assert.Error(err, "invalid parameter values should fail")

	// invalid config
	invalidHasher := NewScryptHasher(0, 0, NewScryptConfig(0, 0, 0))
	hash, err = invalidHasher.Hash(key)
	assert.Equal("", hash, "invalid config should fail")
	assert.Error(err, "invalid config should fail")
}

//func Benchmark_Verifier(b *testing.B) {
//	key := "password"
//	h, _ := KDF(key)
//	for n := 0; n < b.N; n++ {
//		hasher.Verify(key, h)
//	}
//}
