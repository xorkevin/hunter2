package hunter2

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
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
	return fmt.Sprintf("%0*d", length, bin%uint64(math.Pow10(length))), nil
}

func truncate(sum []byte) uint64 {
	offset := uint64(sum[len(sum)-1] & 0xf)
	return ((uint64(sum[offset]) & 0x7f) << 24) |
		((uint64(sum[offset+1] & 0xff)) << 16) |
		((uint64(sum[offset+2] & 0xff)) << 8) |
		(uint64(sum[offset+3]) & 0xff)
}
