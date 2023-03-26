package h2streamcipher

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"hash"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/kerrors"
)

type (
	mockStream struct {
		key byte
	}
)

func (s *mockStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("dst shorter than src")
	}
	for n, i := range src {
		dst[n] = i ^ s.key
	}
}

type (
	mockMAC struct {
		h hash.Hash
	}
)

func (m *mockMAC) Write(src []byte) (int, error) {
	return m.h.Write(src)
}

func (m *mockMAC) Close() error {
	_, err := io.WriteString(m.h, "done")
	return err
}

func (m *mockMAC) Tag() string {
	return base64.RawURLEncoding.EncodeToString(m.h.Sum(nil))
}

func (m *mockMAC) Verify(tagstr string) (bool, error) {
	tag, err := base64.RawURLEncoding.DecodeString(tagstr)
	if err != nil {
		return false, err
	}
	b := m.h.Sum(nil)
	return hmac.Equal(b, tag), nil
}

type (
	mockBuilder struct{}
)

func (b mockBuilder) ID() string {
	return "test"
}

func (b mockBuilder) Build(params string) (KeyStream, MAC, error) {
	if !strings.HasPrefix(params, "$test$") {
		return nil, nil, kerrors.WithKind(nil, ErrKeyInvalid, "Invalid key")
	}
	key := strings.TrimPrefix(params, "$test$")[0]
	bh, err := blake2b.New512([]byte{key})
	if err != nil {
		return nil, nil, kerrors.WithMsg(err, "Failed to create mac")
	}
	stream := &mockStream{
		key: key,
	}
	mac := &mockMAC{
		h: bh,
	}
	return stream, mac, nil
}

func TestEncDecStreams(t *testing.T) {
	t.Parallel()

	testAlgs := NewAlgsMap()
	testAlgs.Register(mockBuilder{})

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

			stream := &mockStream{
				key: 42,
			}
			bh, err := blake2b.New512([]byte{42})
			assert.NoError(err)

			encreader := NewEncStreamReader(stream, &mockMAC{
				h: bh,
			}, strings.NewReader(tc.Plaintext))
			var ciphertext bytes.Buffer
			_, err = io.Copy(&ciphertext, encreader)
			assert.NoError(err)
			assert.NoError(encreader.Close())
			tag := encreader.Tag()

			{
				decreader, err := NewDecStreamReaderFromParams("$test$*", testAlgs, &ciphertext)
				assert.NoError(err)
				var plaintext bytes.Buffer
				_, err = io.Copy(&plaintext, decreader)
				assert.NoError(err)
				assert.NoError(decreader.Close())
				ok, err := decreader.Verify(tag)
				assert.NoError(err)
				assert.True(ok)
				assert.Equal(tc.Plaintext, plaintext.String())
			}
		})
	}
}
