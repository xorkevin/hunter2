package hunter2

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"
)

type (
	// HS512Key implements SigningKey for HS512
	HS512Key struct {
		kid string
		key []byte
	}
)

func (k *HS512Key) Alg() string {
	return SigningAlgHS512
}

func (k *HS512Key) ID() string {
	return k.kid
}

func (k *HS512Key) Private() crypto.PrivateKey {
	return k.key
}

func (k *HS512Key) Public() crypto.PublicKey {
	return k.key
}

// HS512FromParams creates an HS512 key from params
func HS512FromParams(params string) (SigningKey, error) {
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 2 || b[0] != SigningAlgHS512 {
		return nil, fmt.Errorf("%w: Invalid params format", ErrSigningKeyInvalid)
	}
	key, err := base64.RawURLEncoding.DecodeString(b[1])
	if err != nil {
		return nil, fmt.Errorf("Invalid hs512 key: %w", err)
	}
	return &HS512Key{
		kid: signingKeyID(params),
		key: key,
	}, nil
}
