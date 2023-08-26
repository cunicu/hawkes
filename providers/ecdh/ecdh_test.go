// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ecdh_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"cunicu.li/go-skes/providers/ecdh"
	pivx "cunicu.li/go-skes/providers/ecdh/piv"
	"github.com/go-piv/piv-go/piv"
	"github.com/katzenpost/nyquist/dh"
	"github.com/stretchr/testify/require"
)

func testKeypair(t *testing.T, kpAlice dh.Keypair) {
	require := require.New(t)

	kpBob, err := ecdh.P256.GenerateKeypair(rand.Reader)
	require.NoError(err)

	pkAlice := kpAlice.Public()
	pkBob := kpBob.Public()

	t.Logf("Public key Alice: %s", base64.RawStdEncoding.EncodeToString(pkAlice.Bytes()))
	t.Logf("Public key Bob: %s", base64.RawStdEncoding.EncodeToString(pkBob.Bytes()))

	require.Len(pkAlice.Bytes(), 65)
	require.Len(pkBob.Bytes(), 65)

	ssAlice, err := kpAlice.DH(pkBob)
	require.NoError(err)

	ssBob, err := kpBob.DH(pkAlice)
	require.NoError(err)

	t.Logf("Shared secret Alice: %s", base64.RawStdEncoding.EncodeToString(ssAlice))
	t.Logf("Shared secret Bob: %s", base64.RawStdEncoding.EncodeToString(ssBob))

	require.Len(ssAlice, 32)
	require.Len(ssBob, 32)
	require.Equal(ssAlice, ssBob)
}

func TestKeyPairPIV(t *testing.T) {
	require := require.New(t)

	kpAlice, err := pivx.NewKeypair(pivx.Config{
		PIN:  "123456",
		Slot: piv.SlotAuthentication.Key,
	})
	require.NoError(err)

	testKeypair(t, kpAlice)
}
