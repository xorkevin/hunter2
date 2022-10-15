package hunter2

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

type (
	// EdDSAKey implements SigningKey for ED25519 EdDSA
	EdDSAKey struct {
		kid string
		key ed25519.PrivateKey
		pub crypto.PublicKey
	}
)

func (k *EdDSAKey) Alg() string {
	return SigningAlgEdDSA
}

func (k *EdDSAKey) ID() string {
	return k.kid
}

func (k *EdDSAKey) Private() crypto.PrivateKey {
	return k.key
}

func (k *EdDSAKey) Public() crypto.PublicKey {
	return k.pub
}

// EdDSAFromParams creates an ED25519 EdDSA key from params
func EdDSAFromParams(params string) (SigningKey, error) {
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigningAlgEdDSA {
		return nil, fmt.Errorf("%w: Invalid params format", ErrSigningKeyInvalid)
	}
	pemBlock, rest := pem.Decode([]byte(b[1]))
	if pemBlock == nil || pemBlock.Type != privateKeyBlockType || len(rest) != 0 {
		return nil, fmt.Errorf("%w: Invalid ed25519 key pem", ErrSigningKeyInvalid)
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Invalid pkcs8 ed25519 key: %w", err)
	}
	key, ok := rawKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: Invalid created pkcs8 ed25519 key", ErrSigningKeyInvalid)
	}
	return &EdDSAKey{
		kid: signingKeyID(params),
		key: key,
		pub: key.Public(),
	}, nil
}

type (
	// EdDSAPubKey implements VerifierKey for ED25519 EdDSA
	EdDSAPubKey struct {
		kid string
		pub crypto.PublicKey
	}
)

func (k *EdDSAPubKey) Alg() string {
	return SigningAlgEdDSA
}

func (k *EdDSAPubKey) ID() string {
	return k.kid
}

func (k *EdDSAPubKey) Public() crypto.PublicKey {
	return k.pub
}

// EdDSAVerifierFromParams creates an ED25519 EdDSA verifier from params
func EdDSAVerifierFromParams(params string) (VerifierKey, error) {
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigningAlgEdDSA {
		return nil, fmt.Errorf("%w: Invalid params format", ErrSigningKeyInvalid)
	}
	pemBlock, rest := pem.Decode([]byte(b[1]))
	if pemBlock == nil || pemBlock.Type != publicKeyBlockType || len(rest) != 0 {
		return nil, fmt.Errorf("%w: Invalid ed25519 key pem", ErrSigningKeyInvalid)
	}
	rawKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Invalid pkix ed25519 key: %w", err)
	}
	pub, ok := rawKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: Invalid created pkix ed25519 key", ErrVerifierKeyInvalid)
	}
	return &EdDSAPubKey{
		kid: signingKeyID(params),
		pub: pub,
	}, nil
}
