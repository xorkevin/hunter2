package hunter2

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrOTPInvalidOpt is returned when an invalid opt is passed to otp
	ErrOTPInvalidOpt = errors.New("OTP invalid opt")
	// ErrOTPOptUnsupported is returned when an otp opt is unsupported
	ErrOTPOptUnsupported = errors.New("OTP opt unsupported")
	// ErrOTPParamInvalid is returned when an otp param string is invalid
	ErrOTPParamInvalid = errors.New("OTP invalid param")
)

type (
	// HashConstructor constructs a new hash
	HashConstructor = func() hash.Hash
)

// HOTP implements RFC4226
func HOTP(secret []byte, counter uint64, alg HashConstructor, digits int) (string, error) {
	text := make([]byte, 8)
	binary.BigEndian.PutUint64(text, counter)
	h := hmac.New(alg, secret)
	if _, err := h.Write(text); err != nil {
		return "", fmt.Errorf("Failed to hash counter: %w", err)
	}
	sum := h.Sum(nil)
	bin := otpTruncate(sum)
	return formatNumToString(bin, digits), nil
}

func otpTruncate(sum []byte) uint64 {
	offset := uint64(sum[len(sum)-1] & 0xf)
	return ((uint64(sum[offset]) & 0x7f) << 24) |
		((uint64(sum[offset+1] & 0xff)) << 16) |
		((uint64(sum[offset+2] & 0xff)) << 8) |
		(uint64(sum[offset+3]) & 0xff)
}

func formatNumToString(num uint64, digits int) string {
	k := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		k[i] = byte(num%10 + '0')
		num /= 10
	}
	return string(k)
}

// GenerateRandomCode generates a random code with a specified length
func GenerateRandomCode(digits int) (string, error) {
	text := make([]byte, 8)
	if _, err := rand.Read(text); err != nil {
		return "", fmt.Errorf("Failed to generate random code: %w", err)
	}
	num := binary.BigEndian.Uint64(text)
	return formatNumToString(num, digits), nil
}

type (
	// TOTPOpts are opts for TOTP
	TOTPOpts struct {
		Alg    HashConstructor
		Digits int
		Period uint64
	}
)

// TOTP implements RFC6238
func TOTP(secret []byte, t uint64, opts TOTPOpts) (string, error) {
	if opts.Period == 0 {
		return "", fmt.Errorf("%w: invalid period", ErrOTPInvalidOpt)
	}
	return HOTP(secret, t/opts.Period, opts.Alg, opts.Digits)
}

// TOTPNow returns the TOTP now
func TOTPNow(secret []byte, opts TOTPOpts) (string, error) {
	return TOTP(secret, uint64(time.Now().Round(0).Unix()), opts)
}

type (
	// TOTPConfig are opts for TOTP
	TOTPConfig struct {
		Secret []byte
		Alg    string
		Digits int
		Period uint64
		Leeway uint64
	}

	// TOTPURI are opts for OTP apps
	TOTPURI struct {
		TOTPConfig
		Issuer      string
		AccountName string
	}
)

func (c TOTPConfig) String() string {
	b := strings.Builder{}
	b.WriteString("$totp$")
	b.WriteString(c.Alg)
	b.WriteString(",")
	b.WriteString(strconv.Itoa(c.Digits))
	b.WriteString(",")
	b.WriteString(strconv.FormatUint(c.Period, 10))
	b.WriteString(",")
	b.WriteString(strconv.FormatUint(c.Leeway, 10))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(c.Secret))
	return b.String()
}

func (c *TOTPConfig) decodeParams(params string) error {
	b := strings.Split(strings.TrimPrefix(params, "$"), "$")
	if len(b) != 3 || b[0] != "totp" {
		return fmt.Errorf("%w: invalid totp params format", ErrOTPParamInvalid)
	}
	p := strings.Split(b[1], ",")
	if len(p) != 4 {
		return fmt.Errorf("%w: invalid totp params format", ErrOTPParamInvalid)
	}
	c.Alg = p[0]
	var err error
	c.Digits, err = strconv.Atoi(p[1])
	if err != nil {
		return fmt.Errorf("%w: invalid digits", ErrOTPParamInvalid)
	}
	c.Period, err = strconv.ParseUint(p[2], 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid period", ErrOTPParamInvalid)
	}
	c.Leeway, err = strconv.ParseUint(p[3], 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid leeway", ErrOTPParamInvalid)
	}
	c.Secret, err = base64.RawURLEncoding.DecodeString(b[2])
	if err != nil {
		return fmt.Errorf("Invalid secret: %w", err)
	}
	return nil
}

var (
	base32RawEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

func (c TOTPURI) String() string {
	var p string
	q := url.Values{}
	q.Set("secret", base32RawEncoding.EncodeToString(c.Secret))
	q.Set("algorithm", c.Alg)
	if c.Issuer != "" {
		q.Set("issuer", c.Issuer)
		p = fmt.Sprintf("%s:%s", c.Issuer, c.AccountName)
	} else {
		p = c.AccountName
	}
	q.Set("digits", strconv.Itoa(c.Digits))
	q.Set("period", strconv.FormatUint(c.Period, 10))
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     p,
		RawQuery: q.Encode(),
	}
	return u.String()
}

const (
	// TOTPPeriodDefault is the default TOTP period
	TOTPPeriodDefault uint64 = 30
	// OTPDigitsDefault is the default OTP length
	OTPDigitsDefault = 6
)

// TOTPGenerateSecret generates an otp secret
func TOTPGenerateSecret(secretLength int, opts TOTPURI) (string, string, error) {
	opts.Secret = make([]byte, secretLength)
	if _, err := rand.Read(opts.Secret); err != nil {
		return "", "", fmt.Errorf("Failed to generate totp secret: %w", err)
	}
	if opts.Alg == "" {
		opts.Alg = OTPAlgSHA1
	}
	if opts.Digits == 0 {
		opts.Digits = OTPDigitsDefault
	}
	if opts.Period == 0 {
		opts.Period = TOTPPeriodDefault
	}
	return opts.TOTPConfig.String(), opts.String(), nil
}

type (
	// OTPHashes are a map of valid hashes
	OTPHashes interface {
		Get(id string) (HashConstructor, bool)
	}

	otpHashes map[string]HashConstructor
)

func (o otpHashes) Get(id string) (HashConstructor, bool) {
	h, ok := o[id]
	return h, ok
}

// OTP hash algorithms
const (
	OTPAlgSHA1   = "SHA1"
	OTPAlgSHA256 = "SHA256"
	OTPAlgSHA512 = "SHA512"
)

var (
	// DefaultOTPHashes are the hashes defined by RFC6238
	DefaultOTPHashes = otpHashes{
		OTPAlgSHA1:   crypto.SHA1.New,
		OTPAlgSHA256: crypto.SHA256.New,
		OTPAlgSHA512: crypto.SHA512.New,
	}
)

// TOTPVerify verifies an otp
func TOTPVerify(params string, code string, hashes OTPHashes) (bool, error) {
	config := TOTPConfig{}
	if err := config.decodeParams(params); err != nil {
		return false, err
	}
	h, ok := hashes.Get(config.Alg)
	if !ok {
		return false, fmt.Errorf("%w: invalid alg", ErrOTPOptUnsupported)
	}
	now := uint64(time.Now().Round(0).Unix())
	opts := TOTPOpts{
		Alg:    h,
		Digits: config.Digits,
		Period: config.Period,
	}
	for i := uint64(0); i <= config.Leeway; i += opts.Period {
		totp, err := TOTP(config.Secret, now-i, opts)
		if err != nil {
			return false, err
		}
		if hmac.Equal([]byte(totp), []byte(code)) {
			return true, nil
		}
	}
	return false, nil
}
