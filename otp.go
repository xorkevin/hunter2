package hunter2

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrOTPInvalidOpt = errors.New("OTP invalid opt")
)

type (
	// HOTPOpts are opts for HOTP
	HOTPOpts struct {
		Alg crypto.Hash
		Len int
	}
)

// HOTP implements RFC4226
func HOTP(secret string, counter uint64, opts HOTPOpts) (string, error) {
	text := make([]byte, 8)
	binary.BigEndian.PutUint64(text, counter)
	key, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	h := hmac.New(opts.Alg.New, key)
	if _, err := h.Write(text); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	bin := truncate(sum)
	return formatNumToString(bin, opts.Len), nil
}

func truncate(sum []byte) uint64 {
	offset := uint64(sum[len(sum)-1] & 0xf)
	return ((uint64(sum[offset]) & 0x7f) << 24) |
		((uint64(sum[offset+1] & 0xff)) << 16) |
		((uint64(sum[offset+2] & 0xff)) << 8) |
		(uint64(sum[offset+3]) & 0xff)
}

func formatNumToString(num uint64, length int) string {
	k := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		k[i] = byte(num%10 + '0')
		num /= 10
	}
	return string(k)
}

type (
	// TOTPOpts are opts for TOTP
	TOTPOpts struct {
		HOTPOpts
		Period uint64
	}
)

// TOTP implements RFC6238
func TOTP(secret string, t uint64, opts TOTPOpts) (string, error) {
	if opts.Period == 0 {
		return "", fmt.Errorf("%w: invalid period", ErrOTPInvalidOpt)
	}
	return HOTP(secret, t/opts.Period, opts.HOTPOpts)
}

func parseHashAlg(name string) (crypto.Hash, error) {
	switch name {
	case "SHA1":
		return crypto.SHA1, nil
	case "SHA256":
		return crypto.SHA256, nil
	case "SHA512":
		return crypto.SHA512, nil
	default:
		var k crypto.Hash
		return k, fmt.Errorf("%w: invalid alg", ErrOTPInvalidOpt)
	}
}
