package hunter2

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
)

// HOTP implements RFC4226
func HOTP(secret string, counter uint64, alg crypto.Hash, length int) (string, error) {
	text := make([]byte, 8)
	binary.BigEndian.PutUint64(text, counter)
	key, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	h := hmac.New(alg.New, key)
	if _, err := h.Write(text); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	bin := truncate(sum)
	return formatNumToString(bin, length), nil
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
