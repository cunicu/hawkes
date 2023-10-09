// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package handshake_test

import (
	"context"
	"crypto/rand"
	"testing"

	"cunicu.li/hawkes/ecdh"
	"cunicu.li/hawkes/ecdh/sw"
	"cunicu.li/hawkes/handshake"
	"github.com/katzenpost/nyquist"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestHandshake(t *testing.T) {
	require := require.New(t)

	p1, p2 := handshake.NewInprocessPipe()

	kp1, err := sw.P256.GenerateKeypair(rand.Reader)
	require.NoError(err)

	kp2, err := sw.P256.GenerateKeypair(rand.Reader)
	require.NoError(err)

	proto, err := nyquist.NewProtocol("Noise_XX_P-256_ChaChaPoly_BLAKE2s")
	require.NoError(err)

	skp1 := &ecdh.StaticKeypair{
		PrivateKey: kp1,
	}

	skp2 := &ecdh.StaticKeypair{
		PrivateKey: kp2,
	}

	hs1, err := handshake.NewNoiseHandshake(proto, skp1, nil, p1, true)
	require.NoError(err)

	hs2, err := handshake.NewNoiseHandshake(proto, skp2, nil, p2, false)
	require.NoError(err)

	var ss1, ss2 []byte
	var g errgroup.Group

	g.Go(func() (err error) {
		ss1, err = hs1.Secret(context.Background())
		return err
	})

	g.Go(func() (err error) {
		ss2, err = hs2.Secret(context.Background())
		return err
	})

	err = g.Wait()
	require.NoError(err)

	require.Equal(ss1, ss2)
}
