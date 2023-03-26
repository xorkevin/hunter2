package rs256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"xorkevin.dev/hunter2/h2signer"
	"xorkevin.dev/kerrors"
)

const (
	SigID = "rs256"
)

type (
	Config struct {
		Key *rsa.PrivateKey
	}
)

func NewConfig() (*Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate rsa key")
	}
	return &Config{
		Key: key,
	}, nil
}

func (c Config) String() (string, error) {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(SigID)
	b.WriteString("$")
	rawKey, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return "", kerrors.WithMsg(err, "Failed to marshal rsa key")
	}
	b.Write(pem.EncodeToMemory(&pem.Block{
		Type:  h2signer.PEMBlockTypePrivateKey,
		Bytes: rawKey,
	}))
	return b.String(), nil
}

func ParseConfig(params string) (*Config, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2signer.ErrSigningKeyInvalid, "Invalid rsa key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigID {
		return nil, kerrors.WithKind(nil, h2signer.ErrSigningKeyInvalid, "Invalid rsa key")
	}
	pemBlock, rest := pem.Decode([]byte(b[1]))
	if pemBlock == nil || pemBlock.Type != h2signer.PEMBlockTypePrivateKey || len(rest) != 0 {
		return nil, kerrors.WithKind(nil, h2signer.ErrSigningKeyInvalid, "Invalid rsa key pem")
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, kerrors.WithKind(err, h2signer.ErrSigningKeyInvalid, "Invalid pkcs8 rsa key")
	}
	key, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, kerrors.WithKind(nil, h2signer.ErrSigningKeyInvalid, "Invalid pkcs8 rsa key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Key implements SigningKey for RS256
	Key struct {
		kid string
		key *rsa.PrivateKey
		pub crypto.PublicKey
	}
)

func New(config Config) (*Key, error) {
	k := config.Key
	k.Precompute()
	params, err := config.String()
	if err != nil {
		return nil, err
	}
	return &Key{
		kid: h2signer.KeyID(params),
		key: k,
		pub: k.Public(),
	}, nil
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
	return k.pub
}

// NewFromParams creates an RS256 key from params
func NewFromParams(params string) (*Key, error) {
	config, err := ParseConfig(params)
	if err != nil {
		return nil, err
	}
	return New(*config)
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
