package chacha20

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"xorkevin.dev/hunter2/h2streamcipher"
)

func TestStream_Write(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	config, err := NewConfig()
	assert.NoError(err)
	assert.NotNil(config)
	key := config.String()

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

			stream, err := NewStream(*config)
			assert.NoError(err)
			mac, err := NewPoly1305Auth(*config)
			assert.NoError(err)

			encreader := h2streamcipher.NewEncStreamReader(stream, mac, strings.NewReader(tc.Plaintext))
			var ciphertext bytes.Buffer
			_, err = io.Copy(&ciphertext, encreader)
			assert.NoError(err)
			assert.NoError(encreader.Close())
			tag := encreader.Tag()

			{
				config, err := ParseConfig(key)
				assert.NoError(err)
				assert.NotNil(config)
				stream, err := NewStream(*config)
				assert.NoError(err)
				mac, err := NewPoly1305Auth(*config)
				assert.NoError(err)
				decreader := h2streamcipher.NewDecStreamReader(stream, mac, &ciphertext)
				assert.NoError(err)
				plaintext := &bytes.Buffer{}
				_, err = io.Copy(plaintext, decreader)
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
