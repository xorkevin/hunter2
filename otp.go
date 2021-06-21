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
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OTP errors
var (
	ErrOTPInvalidOpt     = errors.New("OTP invalid opt")
	ErrOTPParamInvalid   = errors.New("OTP invalid param")
	ErrOTPOptUnsupported = errors.New("OTP opt unsupported")
)

type (
	// HOTPOpts are opts for HOTP
	HOTPOpts struct {
		Alg crypto.Hash
		Len int
	}
)

// HOTP implements RFC4226
func HOTP(secret []byte, counter uint64, opts HOTPOpts) (string, error) {
	text := make([]byte, 8)
	binary.BigEndian.PutUint64(text, counter)
	h := hmac.New(opts.Alg.New, secret)
	if _, err := h.Write(text); err != nil {
		return "", fmt.Errorf("Failed hash counter: %w", err)
	}
	sum := h.Sum(nil)
	bin := otpTruncate(sum)
	return formatNumToString(bin, opts.Len), nil
}

func otpTruncate(sum []byte) uint64 {
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
func TOTP(secret []byte, t uint64, opts TOTPOpts) (string, error) {
	if opts.Period == 0 {
		return "", fmt.Errorf("%w: invalid period", ErrOTPInvalidOpt)
	}
	return HOTP(secret, t/opts.Period, opts.HOTPOpts)
}

// TOTPNow returns the TOTP now
func TOTPNow(secret string, opts TOTPOpts) (string, error) {
	key, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("Invalid otp secret: %w", err)
	}
	return TOTP(key, uint64(time.Now().Round(0).Unix()), opts)
}

const (
	// TOTPPeriodDefault is the default TOTP period
	TOTPPeriodDefault uint64 = 30
	// OTPDigitsDefault is the default OTP length
	OTPDigitsDefault = 6
)

type (
	// OTPOpts are opts for OTP
	OTPOpts struct {
		Kind   string
		Alg    string
		Digits int
		Period uint64
		Leeway uint64
	}

	// OTPURIOpts are opts for OTP apps
	OTPURIOpts struct {
		OTPOpts
		Issuer      string
		AccountName string
	}
)

// OTP kinds
const (
	OTPKindTOTP = "totp"
)

var (
	otpKinds = map[string]struct{}{
		OTPKindTOTP: {},
	}
)

// OTP hash algorithms
const (
	OTPAlgSHA1   = "SHA1"
	OTPAlgSHA256 = "SHA256"
	OTPAlgSHA512 = "SHA512"
)

var (
	otpAlgs = map[string]struct{}{
		OTPAlgSHA1:   {},
		OTPAlgSHA256: {},
		OTPAlgSHA512: {},
	}
)

// TOTPOpts returns TOTPOpts
func (o OTPOpts) TOTPOpts() (*TOTPOpts, error) {
	alg, err := otpParseHashAlg(o.Alg)
	if err != nil {
		return nil, err
	}
	return &TOTPOpts{
		HOTPOpts: HOTPOpts{
			Alg: alg,
			Len: o.Digits,
		},
		Period: o.Period,
	}, nil
}

func otpURI(secret []byte, opts OTPURIOpts) string {
	var p string
	q := url.Values{}
	q.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret))
	q.Set("algorithm", opts.Alg)
	if opts.Issuer != "" {
		q.Set("issuer", opts.Issuer)
		p = fmt.Sprintf("%s:%s", opts.Issuer, opts.AccountName)
	} else {
		p = opts.AccountName
	}
	q.Set("digits", strconv.Itoa(opts.Digits))
	q.Set("period", strconv.FormatUint(opts.Period, 10))
	u := url.URL{
		Scheme:   "otpauth",
		Host:     opts.Kind,
		Path:     p,
		RawQuery: q.Encode(),
	}
	return u.String()
}

func otpParamsString(secret []byte, opts OTPOpts) string {
	b := strings.Builder{}
	b.WriteString("$")
	b.WriteString(opts.Kind)
	b.WriteString("$")
	b.WriteString(opts.Alg)
	b.WriteString(",")
	b.WriteString(strconv.Itoa(opts.Digits))
	b.WriteString(",")
	b.WriteString(strconv.FormatUint(opts.Period, 10))
	b.WriteString(",")
	b.WriteString(strconv.FormatUint(opts.Leeway, 10))
	b.WriteString("$")
	b.WriteString(base64.RawURLEncoding.EncodeToString(secret))
	return b.String()
}

// OTPGenerateSecret generates an otp secret
func OTPGenerateSecret(secretLength int, opts OTPURIOpts) (string, string, error) {
	secret := make([]byte, secretLength)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
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
	return otpParamsString(secret, opts.OTPOpts), otpURI(secret, opts), nil
}

func otpParseOpts(params string) (*OTPOpts, string, error) {
	opts := &OTPOpts{}
	b := strings.Split(strings.TrimLeft(params, "$"), "$")
	if len(b) != 3 {
		return nil, "", fmt.Errorf("%w: invalid params format", ErrOTPParamInvalid)
	}
	opts.Kind = b[0]
	if _, ok := otpKinds[opts.Kind]; !ok {
		return nil, "", fmt.Errorf("%w: invalid kind %s", ErrOTPParamInvalid, opts.Kind)
	}
	p := strings.Split(b[1], ",")
	if len(p) != 4 {
		return nil, "", fmt.Errorf("%w: invalid params format", ErrOTPParamInvalid)
	}
	secret := b[2]
	opts.Alg = p[0]
	if _, ok := otpAlgs[opts.Alg]; !ok {
		return nil, "", fmt.Errorf("%w: invalid hash alg %s", ErrOTPParamInvalid, opts.Alg)
	}
	var err error
	opts.Digits, err = strconv.Atoi(p[1])
	if err != nil {
		return nil, "", fmt.Errorf("%w: invalid digits", ErrOTPParamInvalid)
	}
	opts.Period, err = strconv.ParseUint(p[2], 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("%w: invalid period", ErrOTPParamInvalid)
	}
	opts.Leeway, err = strconv.ParseUint(p[3], 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("%w: invalid period", ErrOTPParamInvalid)
	}
	return opts, secret, nil
}

func otpParseHashAlg(name string) (crypto.Hash, error) {
	switch name {
	case OTPAlgSHA1:
		return crypto.SHA1, nil
	case OTPAlgSHA256:
		return crypto.SHA256, nil
	case OTPAlgSHA512:
		return crypto.SHA512, nil
	default:
		var k crypto.Hash
		return k, fmt.Errorf("%w: invalid alg %s", ErrOTPOptUnsupported, name)
	}
}

// OTPVerify verifies an otp
func OTPVerify(params string, code string) (bool, error) {
	opts, secret, err := otpParseOpts(params)
	if err != nil {
		return false, err
	}
	key, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return false, fmt.Errorf("Invalid otp secret: %w", err)
	}
	now := uint64(time.Now().Round(0).Unix())
	switch opts.Kind {
	case OTPKindTOTP:
		topts, err := opts.TOTPOpts()
		if err != nil {
			return false, err
		}
		var i uint64 = 0
		for ; i <= opts.Leeway; i += opts.Period {
			totp, err := TOTP(key, now-i, *topts)
			if err != nil {
				return false, err
			}
			if hmac.Equal([]byte(totp), []byte(code)) {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("%w: invalid kind %s", ErrOTPOptUnsupported, opts.Kind)
	}
}
