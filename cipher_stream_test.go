package hunter2

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncDecStreams(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	config, err := NewChaCha20Config()
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

			stream, err := NewChaCha20Stream(*config)
			assert.NoError(err)
			auth, err := NewPoly1305Auth(*config)
			assert.NoError(err)

			encreader := NewEncStreamReader(stream, auth, strings.NewReader(tc.Plaintext))
			b := &bytes.Buffer{}
			_, err = io.Copy(b, encreader)
			assert.NoError(err)
			assert.NoError(auth.WriteCount())
			tag := auth.String()
			ciphertext := b.Bytes()

			{
				config, err := ParseChaCha20Config(key)
				assert.NoError(err)
				assert.NotNil(config)
				stream, err := NewChaCha20Stream(*config)
				assert.NoError(err)
				auth, err := NewPoly1305Auth(*config)
				assert.NoError(err)
				b := &bytes.Buffer{}
				encwriter := NewEncStreamWriter(stream, auth, b)
				assert.NoError(err)
				_, err = io.Copy(encwriter, strings.NewReader(tc.Plaintext))
				assert.NoError(err)
				assert.NoError(auth.WriteCount())
				assert.Equal(ciphertext, b.Bytes())
				assert.Equal(tag, auth.String())
			}

			{
				config, err := ParseChaCha20Config(key)
				assert.NoError(err)
				assert.NotNil(config)
				stream, err := NewChaCha20Stream(*config)
				assert.NoError(err)
				auth, err := NewPoly1305Auth(*config)
				assert.NoError(err)
				decreader := NewDecStreamReader(stream, auth, bytes.NewReader(ciphertext))
				assert.NoError(err)
				plaintext := &bytes.Buffer{}
				_, err = io.Copy(plaintext, decreader)
				assert.NoError(err)
				assert.NoError(auth.WriteCount())
				assert.Equal(tc.Plaintext, plaintext.String())
				assert.NoError(auth.Auth(tag))
			}

			{
				config, err := ParseChaCha20Config(key)
				assert.NoError(err)
				assert.NotNil(config)
				stream, err := NewChaCha20Stream(*config)
				assert.NoError(err)
				auth, err := NewPoly1305Auth(*config)
				assert.NoError(err)
				plaintext := &bytes.Buffer{}
				decwriter := NewDecStreamWriter(stream, auth, plaintext)
				assert.NoError(err)
				_, err = io.Copy(decwriter, bytes.NewReader(ciphertext))
				assert.NoError(err)
				assert.NoError(auth.WriteCount())
				assert.Equal(tc.Plaintext, plaintext.String())
				assert.NoError(auth.Auth(tag))
			}
		})
	}
}
