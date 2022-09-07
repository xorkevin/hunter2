package hunter2

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

type (
	// RS256Key implements SigningKey for RS256
	RS256Key struct {
		kid string
		key *rsa.PrivateKey
		pub crypto.PublicKey
	}
)

func (k *RS256Key) Alg() string {
	return SigningAlgRS256
}

func (k *RS256Key) ID() string {
	return k.kid
}

func (k *RS256Key) Private() crypto.PrivateKey {
	return k.key
}

func (k *RS256Key) Public() crypto.PublicKey {
	return k.pub
}

const (
	rsaPrivateBlockType = "PRIVATE KEY"
)

// RS256FromParams creates an RS256 key from params
func RS256FromParams(params string) (SigningKey, error) {
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigningAlgRS256 {
		return nil, fmt.Errorf("%w: Invalid params format", ErrSigningKeyInvalid)
	}
	pemBlock, rest := pem.Decode([]byte(b[1]))
	if pemBlock == nil || pemBlock.Type != rsaPrivateBlockType || len(rest) != 0 {
		return nil, fmt.Errorf("%w: Invalid rsakey pem", ErrSigningKeyInvalid)
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Invalid pkcs8 rsa key: %w", err)
	}
	key, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: Invalid created pkcs8 rsa key", ErrSigningKeyInvalid)
	}
	key.Precompute()
	return &RS256Key{
		kid: signingKeyID(params),
		key: key,
		pub: key.Public(),
	}, nil
}
