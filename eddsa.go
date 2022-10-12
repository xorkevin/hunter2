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
	if len(b) != 2 || b[0] != SigningAlgRS256 {
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
		return nil, fmt.Errorf("%w: Invalid created pkix ed25519 key", ErrSigningKeyInvalid)
	}
	return &EdDSAPubKey{
		kid: signingKeyID(params),
		pub: pub,
	}, nil
}
