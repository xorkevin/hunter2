package hunter2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESCipher_Encrypt(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	config, err := NewAESConfig("a_key_id", 32)
	assert.NoError(err)
	assert.NotNil(config)
	key := config.String()
	gcm, err := AESCipherFromParams(key)
	assert.NoError(err)
	assert.NotNil(gcm)

	for _, tc := range []struct {
		Plaintext string
	}{
		{
			Plaintext: "hello, world",
		},
		{
			Plaintext: "Lorem ipsum",
		},
	} {
		tc := tc
		t.Run(tc.Plaintext, func(t *testing.T) {
			t.Parallel()

			assert := require.New(t)

			ciphertext, err := gcm.Encrypt(tc.Plaintext)
			assert.NoError(err)
			plaintext, err := gcm.Decrypt(ciphertext)
			assert.NoError(err)
			assert.Equal(tc.Plaintext, plaintext)
		})
	}
}
