// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yawn/ykoath/oath"
	"github.com/yawn/ykoath/ykoath"
)

func TestYkOATH(t *testing.T) {
	require := require.New(t)

	o, err := ykoath.New()
	require.NoError(err)

	s, err := o.Select()
	require.NoError(err)

	t.Logf("Response: %+#v", s)

	names, err := o.List()
	require.NoError(err)

	for _, name := range names {
		t.Logf("%#+v", *name)
	}

	digits := 6

	// key, err := base32.StdEncoding.WithPadding(base32.StdPadding).DecodeString("XFPDG6ZYTQ6OEPKC7JPOUNOJ2DYNJ5KNLAB5K26QGJA3BB2PVWJA====")
	key, err := hex.DecodeString("b95e337b389c3ce23d42fa5eea35c9d0f0d4f54d5803d56bd03241b0874fad92")
	require.NoError(err)
	require.Len(key, 32)

	p, err := oath.New(key, sha256.New)
	require.NoError(err)

	hashOATH := p.CalculateTOTP()
	t.Logf("Hash (oath): %s %s", hex.EncodeToString(hashOATH), truncate(hashOATH, digits))

	err = o.Delete("gotest")
	require.NoError(err)

	err = o.Put("gotest", ykoath.HMACSHA256, ykoath.TOTP, key, false, digits)
	require.NoError(err)

	hashYKOATH, digits, err := o.CalculateTOTP("gotest")
	require.NoError(err)

	t.Logf("Hash (ykoath): %s %s", hex.EncodeToString(hashYKOATH), truncate(hashYKOATH, digits))

	require.Equal(hashOATH, hashYKOATH)

	err = o.Close()
	require.NoError(err)
}

// "Dynamic truncation" in RFC 4226
// http://tools.ietf.org/html/rfc4226#section-5.4
func truncate(sum []byte, digits int) string {
	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	mod := int32(value % int64(math.Pow10(digits)))

	f := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(f, mod)
}
