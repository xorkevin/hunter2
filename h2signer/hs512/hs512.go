package hs512

import (
	"crypto/rand"
	"encoding/base64"
	"strings"

	"xorkevin.dev/hunter2/h2signer"
	"xorkevin.dev/kerrors"
)

const (
	SigID = "hs512"
)

type (
	Config struct {
		Key []byte
	}
)

func NewConfig() (*Config, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate hs512 key")
	}
	return &Config{
		Key: key,
	}, nil
}

func (c Config) String() string {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(SigID)
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Key))
	return b.String()
}

// ParseConfig loads an HS512 config from params string
func ParseConfig(params string) (*Config, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2signer.ErrorSigningKeyInvalid, "Invalid hs512 key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigID {
		return nil, kerrors.WithKind(nil, h2signer.ErrorSigningKeyInvalid, "Invalid hs512 key")
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2signer.ErrorSigningKeyInvalid, "Invalid hs512 key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Key implements [h2signer.SigningKey] for HS512
	Key struct {
		kid string
		key []byte
	}
)

func New(config Config) *Key {
	return &Key{
		kid: h2signer.KeyID(config.String()),
		key: config.Key,
	}
}

func (k *Key) Alg() string {
	return SigID
}

func (k *Key) ID() string {
	return k.kid
}

func (k *Key) Private() interface{} {
	return k.key
}

func (k *Key) Public() interface{} {
	return k.key
}

// NewFromParams creates an HS512 key from params
func NewFromParams(params string) (*Key, error) {
	config, err := ParseConfig(params)
	if err != nil {
		return nil, err
	}
	return New(*config), nil
}

type (
	builder struct{}
)

func (b builder) ID() string {
	return SigID
}

func (b builder) Build(params string) (h2signer.SigningKey, error) {
	return NewFromParams(params)
}

// Register registers a signer alg
func Register(algs h2signer.SigningKeyAlgs) {
	algs.Register(builder{})
}
