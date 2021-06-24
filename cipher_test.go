package hunter2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecrypter(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	keys := make([]string, 0, 2)
	{
		config, err := NewAESConfig()
		assert.NoError(err)
		assert.NotNil(config)
		keys = append(keys, config.String())
	}
	{
		config, err := NewChaCha20Poly1305Config()
		assert.NoError(err)
		assert.NotNil(config)
		keys = append(keys, config.String())
	}

	decrypter := NewDecrypter()
	ciphers := make([]Cipher, 0, 2)
	for _, i := range keys {
		c, err := CipherFromParams(i, DefaultCipherAlgs)
		assert.NoError(err)
		assert.NotNil(c)
		decrypter.RegisterCipher(c)
		ciphers = append(ciphers, c)
	}

	{
		ciphertext, err := ciphers[0].Encrypt("hello, world")
		assert.NoError(err)
		plaintext, err := decrypter.Decrypt(ciphertext)
		assert.NoError(err)
		assert.Equal("hello, world", plaintext)
	}
	{
		ciphertext, err := ciphers[1].Encrypt("Lorem ipsum")
		assert.NoError(err)
		plaintext, err := decrypter.Decrypt(ciphertext)
		assert.NoError(err)
		assert.Equal("Lorem ipsum", plaintext)
	}
}
