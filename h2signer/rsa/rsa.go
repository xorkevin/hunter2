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
		key *rsa.PrivateKey
		pub *PubKey
	}
)

func New(config Config) (*Key, error) {
	k := config.Key
	k.Precompute()
	pk, err := NewPubKey(PubConfig{
		Pub: &k.PublicKey,
	})
	if err != nil {
		return nil, err
	}
	return &Key{
		key: k,
		pub: pk,
	}, nil
}

func (k *Key) Alg() string {
	return SigID
}

func (k *Key) Private() any {
	return k.key
}

func (k *Key) Verifier() h2signer.VerifierKey {
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
	PubConfig struct {
		Pub *rsa.PublicKey
	}
)

func (c PubConfig) String() (string, error) {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(SigID)
	b.WriteString("$")
	rawKey, err := x509.MarshalPKIXPublicKey(c.Pub)
	if err != nil {
		return "", kerrors.WithMsg(err, "Failed to marshal rsa public key")
	}
	b.Write(pem.EncodeToMemory(&pem.Block{
		Type:  h2signer.PEMBlockTypePublicKey,
		Bytes: rawKey,
	}))
	return b.String(), nil
}

func ParsePubConfig(params string) (*PubConfig, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2signer.ErrVerifierKeyInvalid, "Invalid rsa public key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigID {
		return nil, kerrors.WithKind(nil, h2signer.ErrVerifierKeyInvalid, "Invalid rsa public key")
	}
	pemBlock, rest := pem.Decode([]byte(b[1]))
	if pemBlock == nil || pemBlock.Type != h2signer.PEMBlockTypePublicKey || len(rest) != 0 {
		return nil, kerrors.WithKind(nil, h2signer.ErrSigningKeyInvalid, "Invalid rsa public key pem")
	}
	rawKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, kerrors.WithKind(err, h2signer.ErrSigningKeyInvalid, "Invalid pkix rsa public key")
	}
	pub, ok := rawKey.(*rsa.PublicKey)
	if !ok {
		return nil, kerrors.WithKind(nil, h2signer.ErrSigningKeyInvalid, "Invalid pkix rsa public key")
	}
	return &PubConfig{
		Pub: pub,
	}, nil
}

type (
	// PubKey implements VerifierKey for RSA RS256
	PubKey struct {
		kid string
		pub crypto.PublicKey
	}
)

func NewPubKey(config PubConfig) (*PubKey, error) {
	params, err := config.String()
	if err != nil {
		return nil, err
	}
	return &PubKey{
		kid: h2signer.KeyID(params),
		pub: config.Pub,
	}, nil
}

func (k *PubKey) Alg() string {
	return SigID
}

func (k *PubKey) ID() string {
	return k.kid
}

func (k *PubKey) Public() any {
	return k.pub
}

// VerifierFromParams creates an ED25519 EdDSA verifier from params
func VerifierFromParams(params string) (*PubKey, error) {
	config, err := ParsePubConfig(params)
	if err != nil {
		return nil, err
	}
	return NewPubKey(*config)
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

// RegisterSigner registers a signer alg
func RegisterSigner(algs h2signer.SigningKeyAlgs) {
	algs.Register(signerBuilder{})
}

type (
	verifierBuilder struct{}
)

func (b verifierBuilder) ID() string {
	return SigID
}

func (b verifierBuilder) Build(params string) (h2signer.VerifierKey, error) {
	return VerifierFromParams(params)
}

// RegisterVerifier registers a verifier alg
func RegisterVerifier(algs h2signer.VerifierKeyAlgs) {
	algs.Register(verifierBuilder{})
}
