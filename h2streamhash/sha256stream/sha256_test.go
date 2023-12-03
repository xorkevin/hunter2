package sha256stream

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"xorkevin.dev/hunter2/h2streamhash"
)

func TestHasher(t *testing.T) {
	assert := require.New(t)

	testAlgs := h2streamhash.NewAlgsMap()
	Register(testAlgs)

	unkeyedHasher := NewHasher(Config{})
	keyedConfig, err := NewConfig()
	assert.NoError(err)
	keyedHasher, err := h2streamhash.FromParams(keyedConfig.String(), testAlgs)
	assert.NoError(err)

	verifier := h2streamhash.NewVerifier()
	verifier.Register(unkeyedHasher)
	verifier.Register(keyedHasher)

	for _, tc := range []struct {
		Name string
		Hash h2streamhash.Hasher
	}{
		{
			Name: "unkeyed hash",
			Hash: unkeyedHasher,
		},
		{
			Name: "keyed hash",
			Hash: keyedHasher,
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			assert := require.New(t)

			// success case
			hash, err := tc.Hash.Hash()
			assert.NoError(err)
			_, err = io.WriteString(hash, "password")
			assert.NoError(err)
			assert.NoError(hash.Close())
			checksum := hash.Sum()
			// assert can call twice
			checksum = hash.Sum()
			vhash, err := verifier.Verify(checksum)
			assert.NoError(err)
			_, err = io.WriteString(vhash, "password")
			assert.NoError(err)
			assert.NoError(vhash.Close())
			ok, err := vhash.Verify(checksum)
			assert.NoError(err)
			assert.True(ok)
			// assert can call twice
			ok, err = vhash.Verify(checksum)
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
		})
	}
}
