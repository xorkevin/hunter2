package hunter2

import (
	"crypto"
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

Table 2 details for each count the truncated values (both in
hexadecimal and decimal) and then the HOTP value.

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

	secret := "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA"

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
		t.Run(strconv.FormatUint(tc.Counter, 10), func(t *testing.T) {
			t.Parallel()

			assert := require.New(t)
			code, err := HOTP(secret, tc.Counter, crypto.SHA1, 6)
			assert.Nil(err)
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
		t.Run(strconv.FormatUint(tc.Num, 10)+" len "+strconv.Itoa(tc.Len), func(t *testing.T) {
			t.Parallel()

			assert := require.New(t)
			assert.Equal(tc.Str, formatNumToString(tc.Num, tc.Len))
		})
	}
}
