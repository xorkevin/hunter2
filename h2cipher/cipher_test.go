package h2cipher

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"xorkevin.dev/kerrors"
)

type (
	mockCipher struct {
		kid string
	}
)

func (c *mockCipher) ID() string {
	return c.kid
}

func (c *mockCipher) Encrypt(plaintext string) (string, error) {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(c.kid)
	b.WriteString("$test$")
	b.WriteString(base64.RawURLEncoding.EncodeToString([]byte(plaintext)))
	return b.String(), nil
}

func (c *mockCipher) Decrypt(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, "$") {
		return "", kerrors.WithKind(nil, ErrorCiphertextInvalid, "Invalid ciphertext")
	}
	b := strings.Split(strings.TrimPrefix(ciphertext, "$"), "$")
	if len(b) != 3 || b[0] != c.kid || b[1] != "test" {
		return "", kerrors.WithKind(nil, ErrorCiphertextInvalid, "Invalid ciphertext")
	}
	plaintext, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return "", kerrors.WithKind(err, ErrorCiphertextInvalid, "Invalid ciphertext")
	}
	return string(plaintext), nil
}

type (
	mockBuilder struct{}
)

func (b mockBuilder) ID() string {
	return "test"
}

func (b mockBuilder) Build(params string) (Cipher, error) {
	if !strings.HasPrefix(params, "$test$") {
		return nil, kerrors.WithKind(nil, ErrorKeyInvalid, "Invalid key")
	}
	return &mockCipher{
		kid: strings.TrimPrefix(params, "$test$"),
	}, nil
}

func TestKeyring(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	keys := []string{"$test$key1", "$test$key2"}

	decrypter := NewKeyring()
	testAlgs := NewAlgsMap()
	testAlgs.Register(mockBuilder{})

	ciphers := make([]Cipher, 0, 2)
	for _, i := range keys {
		c, err := FromParams(i, testAlgs)
		assert.NoError(err)
		assert.NotNil(c)
		decrypter.Register(c)
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
