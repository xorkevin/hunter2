package hmacsig

import (
	"crypto/rand"
	"encoding/base64"
	"strings"

	"xorkevin.dev/hunter2/h2signer"
	"xorkevin.dev/kerrors"
)

const (
	SigID = "hmac"
)

type (
	Config struct {
		Key []byte
	}
)

func NewConfig() (*Config, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate hs256 key")
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

// ParseConfig loads an HS256 config from params string
func ParseConfig(params string) (*Config, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2signer.ErrSigningKeyInvalid, "Invalid hs256 key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigID {
		return nil, kerrors.WithKind(nil, h2signer.ErrSigningKeyInvalid, "Invalid hs256 key")
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, kerrors.WithKind(err, h2signer.ErrSigningKeyInvalid, "Invalid hs256 key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Key implements [h2signer.SigningKey] for HS256
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

func (k *Key) Private() any {
	return k.key
}

func (k *Key) Verifier() h2signer.VerifierKey {
	return k
}

func (k *Key) Public() any {
	return k.key
}

// NewFromParams creates an HS256 key from params
func NewFromParams(params string) (*Key, error) {
	config, err := ParseConfig(params)
	if err != nil {
		return nil, err
	}
	return New(*config), nil
}

type (
	signerBuilder struct{}
)

func (b signerBuilder) ID() string {
	return SigID
}

func (b signerBuilder) Build(params string) (h2signer.SigningKey, error) {
	return NewFromParams(params)
}

// Register registers a signer alg
func Register(algs h2signer.SigningKeyAlgs) {
	algs.Register(signerBuilder{})
}

type (
	verifierBuilder struct{}
)

func (b verifierBuilder) ID() string {
	return SigID
}

func (b verifierBuilder) Build(params string) (h2signer.VerifierKey, error) {
	return NewFromParams(params)
}

// RegisterVerifier registers a verifier alg
func RegisterVerifier(algs h2signer.VerifierKeyAlgs) {
	algs.Register(verifierBuilder{})
}
