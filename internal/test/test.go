// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"cunicu.li/hawkes/ecdh"
	"cunicu.li/hawkes/ecdh/sw"
)

//nolint:revive
func TestKeypair(t *testing.T, skAlice ecdh.PrivateKey) {
	require := require.New(t)

	kpBob, err := sw.P256.GenerateKeypair(rand.Reader)
	require.NoError(err)

	pkAlice := skAlice.Public()
	pkBob := kpBob.Public()

	t.Logf("Public key Alice: %s", base64.RawStdEncoding.EncodeToString(pkAlice.Bytes()))
	t.Logf("Public key Bob: %s", base64.RawStdEncoding.EncodeToString(pkBob.Bytes()))

	require.Len(pkAlice.Bytes(), 65)
	require.Len(pkBob.Bytes(), 65)

	ssAlice, err := skAlice.DH(pkBob)
	require.NoError(err)

	ssBob, err := kpBob.DH(pkAlice)
	require.NoError(err)

	t.Logf("Shared secret Alice: %s", base64.RawStdEncoding.EncodeToString(ssAlice))
	t.Logf("Shared secret Bob: %s", base64.RawStdEncoding.EncodeToString(ssBob))

	require.Len(ssAlice, 32)
	require.Len(ssBob, 32)
	require.Equal(ssAlice, ssBob)
}
