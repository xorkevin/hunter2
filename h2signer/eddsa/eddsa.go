package eddsa

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"xorkevin.dev/hunter2/h2signer"
	"xorkevin.dev/kerrors"
)

const (
	SigID = "eddsa"
)

type (
	Config struct {
		Key ed25519.PrivateKey
	}
)

func NewConfig() (*Config, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to generate ed25519 key")
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
		return "", kerrors.WithMsg(err, "Failed to marshal ed25519 key")
	}
	b.Write(pem.EncodeToMemory(&pem.Block{
		Type:  h2signer.PEMBlockTypePrivateKey,
		Bytes: rawKey,
	}))
	return b.String(), nil
}

func ParseConfig(params string) (*Config, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2signer.ErrorSigningKeyInvalid, "Invalid ed25519 key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigID {
		return nil, kerrors.WithKind(nil, h2signer.ErrorSigningKeyInvalid, "Invalid ed25519 key")
	}
	pemBlock, rest := pem.Decode([]byte(b[1]))
	if pemBlock == nil || pemBlock.Type != h2signer.PEMBlockTypePrivateKey || len(rest) != 0 {
		return nil, kerrors.WithKind(nil, h2signer.ErrorSigningKeyInvalid, "Invalid ed25519 key pem")
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, kerrors.WithKind(err, h2signer.ErrorSigningKeyInvalid, "Invalid pkcs8 ed25519 key")
	}
	key, ok := rawKey.(ed25519.PrivateKey)
	if !ok {
		return nil, kerrors.WithKind(nil, h2signer.ErrorSigningKeyInvalid, "Invalid pkcs8 ed25519 key")
	}
	return &Config{
		Key: key,
	}, nil
}

type (
	// Key implements SigningKey for ED25519 EdDSA
	Key struct {
		kid string
		key ed25519.PrivateKey
		pub crypto.PublicKey
	}
)

func New(config Config) (*Key, error) {
	k := config.Key
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

// NewFromParams creates an ED25519 EdDSA key from params
func NewFromParams(params string) (*Key, error) {
	config, err := ParseConfig(params)
	if err != nil {
		return nil, err
	}
	return New(*config)
}

type (
	PubConfig struct {
		Pub ed25519.PublicKey
	}
)

func (c PubConfig) String() (string, error) {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(SigID)
	b.WriteString("$")
	rawKey, err := x509.MarshalPKIXPublicKey(c.Pub)
	if err != nil {
		return "", kerrors.WithMsg(err, "Failed to marshal ed25519 public key")
	}
	b.Write(pem.EncodeToMemory(&pem.Block{
		Type:  h2signer.PEMBlockTypePublicKey,
		Bytes: rawKey,
	}))
	return b.String(), nil
}

func ParsePubConfig(params string) (*PubConfig, error) {
	if !strings.HasPrefix(params, "$") {
		return nil, kerrors.WithKind(nil, h2signer.ErrorVerifierKeyInvalid, "Invalid ed25519 public key")
	}
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigID {
		return nil, kerrors.WithKind(nil, h2signer.ErrorVerifierKeyInvalid, "Invalid ed25519 public key")
	}
	pemBlock, rest := pem.Decode([]byte(b[1]))
	if pemBlock == nil || pemBlock.Type != h2signer.PEMBlockTypePublicKey || len(rest) != 0 {
		return nil, kerrors.WithKind(nil, h2signer.ErrorSigningKeyInvalid, "Invalid ed25519 public key pem")
	}
	rawKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, kerrors.WithKind(err, h2signer.ErrorSigningKeyInvalid, "Invalid pkix ed25519 public key")
	}
	pub, ok := rawKey.(ed25519.PublicKey)
	if !ok {
		return nil, kerrors.WithKind(nil, h2signer.ErrorSigningKeyInvalid, "Invalid pkix ed25519 public key")
	}
	return &PubConfig{
		Pub: pub,
	}, nil
}

type (
	// PubKey implements VerifierKey for ED25519 EdDSA
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

func (k *PubKey) Public() interface{} {
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
