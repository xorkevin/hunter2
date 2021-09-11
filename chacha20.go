package hunter2

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

type (
	// ChaCha20Config are chacha20 params
	ChaCha20Config struct {
		Key   []byte
		Nonce []byte
	}
)

// NewChaCha20Config creates a new chacha20 config
func NewChaCha20Config() (*ChaCha20Config, error) {
	key := make([]byte, chacha20.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("Failed to generate chacha20 key: %w", err)
	}
	nonce := make([]byte, chacha20.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("Failed to generate chacha20 nonce: %w", err)
	}
	return &ChaCha20Config{
		Key:   key,
		Nonce: nonce,
	}, nil
}

func (c ChaCha20Config) String() string {
	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(CipherStreamAlgChaCha20)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Key))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Nonce))
	return b.String()
}

// ParseChaCha20Config loads a chacha20 config from params string
func ParseChaCha20Config(params string) (*ChaCha20Config, error) {
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 3 || b[0] != CipherStreamAlgChaCha20 {
		return nil, fmt.Errorf("%w: invalid params format", ErrCipherKeyInvalid)
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, fmt.Errorf("Invalid chacha20 key: %w", err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return nil, fmt.Errorf("Invalid chacha20 nonce: %w", err)
	}
	return &ChaCha20Config{
		Key:   key,
		Nonce: nonce,
	}, nil
}

// NewChaCha20Stream creates a new chacha20 stream cipher
func NewChaCha20Stream(config ChaCha20Config) (cipher.Stream, error) {
	stream, err := chacha20.NewUnauthenticatedCipher(config.Key, config.Nonce)
	if err != nil {
		return nil, fmt.Errorf("Failed to create chacha20 cipher stream: %w", err)
	}
	stream.SetCounter(1)
	return stream, nil
}

type (
	// Poly1305Auth computes a poly1305 auth tag
	Poly1305Auth struct {
		h     *poly1305.MAC
		count uint64
	}
)

// NewPoly1305Auth creates a new poly1305 hash to authenticate a cipher stream
func NewPoly1305Auth(c ChaCha20Config) (*Poly1305Auth, error) {
	s, err := chacha20.NewUnauthenticatedCipher(c.Key, c.Nonce)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate poly1305 key: %w", err)
	}
	s.SetCounter(0)
	polyKey := [32]byte{}
	s.XORKeyStream(polyKey[:], polyKey[:])
	return &Poly1305Auth{
		h:     poly1305.New(&polyKey),
		count: 0,
	}, nil
}

func (a *Poly1305Auth) Write(src []byte) (int, error) {
	n, err := a.h.Write(src)
	if n != len(src) && err == nil {
		// should never happen
		err = io.ErrShortWrite
	}
	a.count += uint64(n)
	return n, err
}

func (a *Poly1305Auth) WriteCount() error {
	if n := a.count % 16; n > 0 {
		// pad length to 16 bytes
		b := make([]byte, 16-n)
		k, err := a.h.Write(b)
		if k != int(n) && err == nil {
			// should never happen
			err = io.ErrShortWrite
		}
		if err != nil {
			// should not happen as specified by hash.Hash
			return err
		}
	}
	return binary.Write(a.h, binary.LittleEndian, a.count)
}

func (a *Poly1305Auth) Sum(b []byte) []byte {
	return a.h.Sum(b)
}

func (a *Poly1305Auth) String() string {
	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(CipherAuthAlgPoly1305)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(a.Sum(nil)))
	return b.String()
}
