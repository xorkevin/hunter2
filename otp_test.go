package hunter2

import (
	"crypto"
	"encoding/base64"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
Secret = 0x3132333435363738393031323334353637383930

Table 1 details for each count, the intermediate HMAC value.

Count    Hexadecimal HMAC-SHA-1(secret, count)
0        cc93cf18508d94934c64b65d8ba7667fb7cde4b0
1        75a48a19d4cbe100644e8ac1397eea747a2d33ab
2        0bacb7fa082fef30782211938bc1c5e70416ff44
3        66c28227d03a2d5529262ff016a1e6ef76557ece
4        a904c900a64b35909874b33e61c5938a8e15ed1c
5        a37e783d7b7233c083d4f62926c7a25f238d0316
6        bc9cd28561042c83f219324d3c607256c03272ae
7        a4fb960c0bc06e1eabb804e5b397cdc4b45596fa
8        1b3c89f65e6c9e883012052823443f048b4332db
9        1637409809a679dc698207310c8c7fc07290d9e5

Table 2 details for each count the truncated values (both in hexadecimal and
decimal) and then the HOTP value.

Truncated

Count    Hexadecimal    Decimal        HOTP
0        4c93cf18       1284755224     755224
1        41397eea       1094287082     287082
2         82fef30        137359152     359152
3        66ef7655       1726969429     969429
4        61c5938a       1640338314     338314
5        33c083d4        868254676     254676
6        7256c032       1918287922     287922
7         4e5b397         82162583     162583
8        2823443f        673399871     399871
9        2679dc69        645520489     520489
*/

func TestHOTP(t *testing.T) {
	t.Parallel()

	assert := require.New(t)
	secret, err := base64.RawURLEncoding.DecodeString("MTIzNDU2Nzg5MDEyMzQ1Njc4OTA")
	assert.NoError(err)

	for _, tc := range []struct {
		Counter uint64
		Code    string
	}{
		{
			Counter: 0,
			Code:    "755224",
		},
		{
			Counter: 1,
			Code:    "287082",
		},
		{
			Counter: 2,
			Code:    "359152",
		},
		{
			Counter: 3,
			Code:    "969429",
		},
		{
			Counter: 4,
			Code:    "338314",
		},
		{
			Counter: 5,
			Code:    "254676",
		},
		{
			Counter: 6,
			Code:    "287922",
		},
		{
			Counter: 7,
			Code:    "162583",
		},
		{
			Counter: 8,
			Code:    "399871",
		},
		{
			Counter: 9,
			Code:    "520489",
		},
	} {
		tc := tc
		t.Run(strconv.FormatUint(tc.Counter, 10), func(t *testing.T) {
			t.Parallel()

			assert := require.New(t)
			code, err := HOTP(secret, tc.Counter, HOTPOpts{
				Alg: crypto.SHA1,
				Len: 6,
			})
			assert.NoError(err)
			assert.Equal(tc.Code, code)
		})
	}
}

func TestFormatNumToString(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		Num uint64
		Len int
		Str string
	}{
		{
			Num: 12345678,
			Len: 6,
			Str: "345678",
		},
		{
			Num: 123,
			Len: 6,
			Str: "000123",
		},
	} {
		tc := tc
		t.Run(strconv.FormatUint(tc.Num, 10)+" len "+strconv.Itoa(tc.Len), func(t *testing.T) {
			t.Parallel()

			assert := require.New(t)
			assert.Equal(tc.Str, formatNumToString(tc.Num, tc.Len))
		})
	}
}

/*
The test token shared secret uses the ASCII string value
"12345678901234567890".  With Time Step X = 30, and the Unix epoch as the
initial value to count time steps, where T0 = 0, the TOTP algorithm will
display the following values for specified modes and timestamps.

+-------------+--------------+------------------+----------+--------+
|  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
+-------------+--------------+------------------+----------+--------+
|      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
|             |   00:00:59   |                  |          |        |
|      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
|             |   00:00:59   |                  |          |        |
|      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
|             |   00:00:59   |                  |          |        |
|  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
|             |   01:58:29   |                  |          |        |
|  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
|             |   01:58:29   |                  |          |        |
|  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
|             |   01:58:29   |                  |          |        |
|  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
|             |   01:58:31   |                  |          |        |
|  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
|             |   01:58:31   |                  |          |        |
|  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
|             |   01:58:31   |                  |          |        |
|  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
|             |   23:31:30   |                  |          |        |
|  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
|             |   23:31:30   |                  |          |        |
|  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
|             |   23:31:30   |                  |          |        |
|  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
|             |   03:33:20   |                  |          |        |
|  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
|             |   03:33:20   |                  |          |        |
|  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
|             |   03:33:20   |                  |          |        |
| 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
|             |   11:33:20   |                  |          |        |
| 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
|             |   11:33:20   |                  |          |        |
| 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
|             |   11:33:20   |                  |          |        |
+-------------+--------------+------------------+----------+--------+

Table 1: TOTP Table
*/

func TestTOTP(t *testing.T) {
	t.Parallel()

	sha1secret := "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA"
	sha256secret := "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI"
	sha512secret := "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA"

	for _, tc := range []struct {
		Secret string
		T      uint64
		Alg    crypto.Hash
		Code   string
	}{
		{
			Secret: sha1secret,
			T:      59,
			Alg:    crypto.SHA1,
			Code:   "94287082",
		},
		{
			Secret: sha256secret,
			T:      59,
			Alg:    crypto.SHA256,
			Code:   "46119246",
		},
		{
			Secret: sha512secret,
			T:      59,
			Alg:    crypto.SHA512,
			Code:   "90693936",
		},
		{
			Secret: sha1secret,
			T:      1111111109,
			Alg:    crypto.SHA1,
			Code:   "07081804",
		},
		{
			Secret: sha256secret,
			T:      1111111109,
			Alg:    crypto.SHA256,
			Code:   "68084774",
		},
		{
			Secret: sha512secret,
			T:      1111111109,
			Alg:    crypto.SHA512,
			Code:   "25091201",
		},
		{
			Secret: sha1secret,
			T:      1111111111,
			Alg:    crypto.SHA1,
			Code:   "14050471",
		},
		{
			Secret: sha256secret,
			T:      1111111111,
			Alg:    crypto.SHA256,
			Code:   "67062674",
		},
		{
			Secret: sha512secret,
			T:      1111111111,
			Alg:    crypto.SHA512,
			Code:   "99943326",
		},
		{
			Secret: sha1secret,
			T:      1234567890,
			Alg:    crypto.SHA1,
			Code:   "89005924",
		},
		{
			Secret: sha256secret,
			T:      1234567890,
			Alg:    crypto.SHA256,
			Code:   "91819424",
		},
		{
			Secret: sha512secret,
			T:      1234567890,
			Alg:    crypto.SHA512,
			Code:   "93441116",
		},
		{
			Secret: sha1secret,
			T:      2000000000,
			Alg:    crypto.SHA1,
			Code:   "69279037",
		},
		{
			Secret: sha256secret,
			T:      2000000000,
			Alg:    crypto.SHA256,
			Code:   "90698825",
		},
		{
			Secret: sha512secret,
			T:      2000000000,
			Alg:    crypto.SHA512,
			Code:   "38618901",
		},
		{
			Secret: sha1secret,
			T:      20000000000,
			Alg:    crypto.SHA1,
			Code:   "65353130",
		},
		{
			Secret: sha256secret,
			T:      20000000000,
			Alg:    crypto.SHA256,
			Code:   "77737706",
		},
		{
			Secret: sha512secret,
			T:      20000000000,
			Alg:    crypto.SHA512,
			Code:   "47863826",
		},
	} {
		tc := tc
		t.Run(strconv.FormatUint(tc.T, 10)+" "+tc.Alg.String(), func(t *testing.T) {
			t.Parallel()

			assert := require.New(t)
			secret, err := base64.RawURLEncoding.DecodeString(tc.Secret)
			assert.NoError(err)
			code, err := TOTP(secret, tc.T, TOTPOpts{
				HOTPOpts: HOTPOpts{
					Alg: tc.Alg,
					Len: 8,
				},
				Period: 30,
			})
			assert.NoError(err)
			assert.Equal(tc.Code, code)
		})
	}
}

func TestOTPParams(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		Secret string
		Opts   OTPURIOpts
		Params string
		URI    string
	}{
		{
			Secret: "hello_world",
			Opts: OTPURIOpts{
				OTPOpts: OTPOpts{
					Kind:   OTPKindTOTP,
					Alg:    OTPAlgSHA1,
					Digits: 6,
					Period: 30,
					Leeway: 0,
				},
				Issuer:      "xorkevin dev",
				AccountName: "kevin",
			},
			Params: "$totp$SHA1,6,30,0$aGVsbG9fd29ybGQ",
			URI:    "otpauth://totp/xorkevin%20dev:kevin?algorithm=SHA1&digits=6&issuer=xorkevin+dev&period=30&secret=NBSWY3DPL53W64TMMQ",
		},
		{
			Secret: "lorem ipsum",
			Opts: OTPURIOpts{
				OTPOpts: OTPOpts{
					Kind:   OTPKindTOTP,
					Alg:    OTPAlgSHA256,
					Digits: 8,
					Period: 15,
					Leeway: 1,
				},
				Issuer:      "governor auth",
				AccountName: "kevin",
			},
			Params: "$totp$SHA256,8,15,1$bG9yZW0gaXBzdW0",
			URI:    "otpauth://totp/governor%20auth:kevin?algorithm=SHA256&digits=8&issuer=governor+auth&period=15&secret=NRXXEZLNEBUXA43VNU",
		},
	} {
		tc := tc
		t.Run(tc.URI, func(t *testing.T) {
			t.Parallel()

			assert := require.New(t)
			assert.Equal(tc.Params, otpParamsString([]byte(tc.Secret), tc.Opts.OTPOpts))
			assert.Equal(tc.URI, otpURI([]byte(tc.Secret), tc.Opts))
			opts, secret, err := otpParseOpts(tc.Params)
			assert.NoError(err)
			assert.NotNil(opts)
			assert.Equal(tc.Opts.OTPOpts, *opts)
			assert.Equal(base64.RawURLEncoding.EncodeToString([]byte(tc.Secret)), secret)
		})
	}
}

func TestOTPGenerateSecret(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	params, _, err := OTPGenerateSecret(64, OTPURIOpts{
		OTPOpts: OTPOpts{
			Kind:   OTPKindTOTP,
			Alg:    OTPAlgSHA1,
			Digits: 6,
			Period: 30,
			Leeway: 1,
		},
		Issuer:      "xorkevin dev",
		AccountName: "kevin",
	})
	assert.NoError(err)
	opts, secret, err := otpParseOpts(params)
	assert.NoError(err)
	topts, err := opts.TOTPOpts()
	assert.NoError(err)
	code, err := TOTPNow(secret, *topts)
	assert.NoError(err)
	ok, err := OTPVerify(params, code)
	assert.NoError(err)
	assert.True(ok)
}
