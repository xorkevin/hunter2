package argon2

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"xorkevin.dev/hunter2/h2hash"
)

func TestHasher(t *testing.T) {
	assert := require.New(t)
	msg := "password"

	hasher := New(16, 16, Config{
		Version:  argon2.Version,
		Time:     2,
		Mem:      1024,
		Parallel: 1,
	})

	assert.Equal(HashID, hasher.ID())

	// success case
	msghash, err := hasher.Hash([]byte(msg))
	assert.NoError(err, "hash should be successful")
	ok, err := hasher.Verify([]byte(msg), msghash)
	assert.True(ok, "msg should be correct")
	assert.NoError(err, "msg should be correct")

	// invalid msg
	ok, err = hasher.Verify([]byte("notpass"), msghash)
	assert.False(ok, "incorrect msg should fail")
	assert.NoError(err, "incorrect msg should not error")

	// invalid hash format
	ok, err = hasher.Verify([]byte(msg), "")
	assert.False(ok, "blank hash should fail")
	assert.ErrorIs(err, h2hash.ErrInvalidFormat, "blank hash should fail")
	ok, err = hasher.Verify([]byte(msg), "$a2id")
	assert.False(ok, "invalid number of hash components should fail")
	assert.ErrorIs(err, h2hash.ErrInvalidFormat, "invalid number of hash components should fail")

	// invalid parameters
	ok, err = hasher.Verify([]byte(msg), "$a2id$$$")
	assert.False(ok, "invalid number of parameters should fail")
	assert.ErrorIs(err, h2hash.ErrInvalidFormat, "invalid number of parameters should fail")

	// invalid config
	invalidHasher := New(0, 0, Config{})
	msghash, err = invalidHasher.Hash([]byte(msg))
	assert.Equal("", msghash, "invalid config should fail")
	assert.Error(err, "invalid config should fail")
}

func BenchmarkHash46(b *testing.B) {
	hasher := New(32, 32, Config{
		Version:  argon2.Version,
		Time:     1,
		Mem:      47104,
		Parallel: 1,
	})

	for n := 0; n < b.N; n++ {
		hasher.exec([]byte("password"), []byte("testsalt"), 32, Config{
			Version:  argon2.Version,
			Time:     1,
			Mem:      47104,
			Parallel: 1,
		})
	}
}

func BenchmarkHash19(b *testing.B) {
	hasher := New(32, 32, Config{
		Version:  argon2.Version,
		Time:     2,
		Mem:      19456,
		Parallel: 1,
	})

	for n := 0; n < b.N; n++ {
		hasher.exec([]byte("password"), []byte("testsalt"), 32, Config{
			Version:  argon2.Version,
			Time:     2,
			Mem:      19456,
			Parallel: 1,
		})
	}
}

func BenchmarkHash12(b *testing.B) {
	hasher := New(32, 32, Config{
		Version:  argon2.Version,
		Time:     3,
		Mem:      12288,
		Parallel: 1,
	})

	for n := 0; n < b.N; n++ {
		hasher.exec([]byte("password"), []byte("testsalt"), 32, Config{
			Version:  argon2.Version,
			Time:     3,
			Mem:      12288,
			Parallel: 1,
		})
	}
}

func BenchmarkHash9(b *testing.B) {
	hasher := New(32, 32, Config{
		Version:  argon2.Version,
		Time:     4,
		Mem:      9216,
		Parallel: 1,
	})

	for n := 0; n < b.N; n++ {
		hasher.exec([]byte("password"), []byte("testsalt"), 32, Config{
			Version:  argon2.Version,
			Time:     4,
			Mem:      9216,
			Parallel: 1,
		})
	}
}

func BenchmarkHash7(b *testing.B) {
	hasher := New(32, 32, Config{
		Version:  argon2.Version,
		Time:     5,
		Mem:      7168,
		Parallel: 1,
	})

	for n := 0; n < b.N; n++ {
		hasher.exec([]byte("password"), []byte("testsalt"), 32, Config{
			Version:  argon2.Version,
			Time:     5,
			Mem:      7168,
			Parallel: 1,
		})
	}
}
