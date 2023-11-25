package xchacha20

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"xorkevin.dev/hunter2/h2streamcipher"
)

func TestStream_Write(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	config, err := NewConfig()
	assert.NoError(err)
	assert.NotNil(config)
	key := config.String()

	algs := h2streamcipher.NewAlgsMap()
	Register(algs)

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

			stream, mac, err := NewFromParams(key)
			assert.NoError(err)

			encreader := h2streamcipher.NewEncStreamReader(stream, mac, strings.NewReader(tc.Plaintext))
			var ciphertext bytes.Buffer
			_, err = io.Copy(&ciphertext, encreader)
			assert.NoError(err)
			assert.NoError(encreader.Close())
			tag := encreader.Tag()

			{
				decreader, err := h2streamcipher.NewDecStreamReaderFromParams(key, algs, &ciphertext)
				assert.NoError(err)
				var plaintext bytes.Buffer
				_, err = io.Copy(&plaintext, decreader)
				assert.NoError(err)
				assert.NoError(decreader.Close())
				assert.Equal(tc.Plaintext, plaintext.String())
				ok, err := decreader.Verify(tag)
				assert.NoError(err)
				assert.True(ok)
			}
		})
	}
}

func TestVectors(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	assert.NoError(err)

	targetCipher, err := chacha20poly1305.NewX(key)
	assert.NoError(err)

	nonce := make([]byte, targetCipher.NonceSize())
	_, err = rand.Read(nonce)
	assert.NoError(err)

	targetVector := targetCipher.Seal(nil, nonce, []byte("Hello, world"), nil)

	stream, auth, err := NewFromConfig(Config{
		Key:   key,
		Nonce: nonce,
	})
	assert.NoError(err)

	ciphertext := []byte("Hello, world")
	stream.XORKeyStream(ciphertext[:], ciphertext[:])
	_, err = auth.Write(ciphertext)
	assert.NoError(err)
	assert.NoError(auth.Close())

	assert.Len(targetVector, len(ciphertext)+poly1305.TagSize)
	assert.Equal(targetVector[:len(ciphertext)], ciphertext)
	tag, err := ParsePoly1305Tag(auth.Tag())
	assert.NoError(err)
	assert.Equal(targetVector[len(ciphertext):], tag)
}
