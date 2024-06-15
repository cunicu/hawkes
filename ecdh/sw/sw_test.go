// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package sw_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"cunicu.li/hawkes/ecdh/sw"
	"cunicu.li/hawkes/internal/test"
)

func TestSoftware(t *testing.T) {
	require := require.New(t)

	kpAlice, err := sw.P256.GenerateKeypair(rand.Reader)
	require.NoError(err)

	test.ECDH(t, kpAlice)
}
