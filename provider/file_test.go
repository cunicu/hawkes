// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemory(t *testing.T) {
	require := require.New(t)

	p, err := newFileProvider()
	require.NoError(err)

	keys, err := p.Keys()
	require.NoError(err)
	require.Empty(keys)

	id1, err := p.CreateKey("test1")
	require.NoError(err)
	require.NotNil(id1)

	defer func() {
		err := p.DestroyKey(id1)
		require.NoError(err)
	}()

	id2, err := p.CreateKey("test2")
	require.NoError(err)
	require.NotNil(id2)

	defer func() {
		err := p.DestroyKey(id2)
		require.NoError(err)
	}()

	_, err = p.CreateKey("test1")
	require.ErrorIs(err, os.ErrExist)

	key1, err := p.OpenKey(id1)
	require.NoError(err)
	require.Equal(key1.ID(), id1)

	defer func() {
		err := key1.Close()
		require.NoError(err)
	}()

	key2, err := p.OpenKey(id2)
	require.NoError(err)
	require.Equal(key2.ID(), id2)

	defer func() {
		err := key2.Close()
		require.NoError(err)
	}()

	keyDH1, ok := key1.(PrivateKeyDH)
	require.True(ok)

	keyDH2, ok := key2.(PrivateKeyDH)
	require.True(ok)

	keyHMAC, ok := key1.(PrivateKeyHMAC)
	require.True(ok)

	hmac, err := keyHMAC.HMAC([]byte{})
	require.NoError(err)
	require.Len(hmac, 32)

	ss1, err := keyDH1.DH(keyDH2.Public())
	require.NoError(err)

	ss2, err := keyDH2.DH(keyDH1.Public())
	require.NoError(err)

	require.Equal(ss1, ss2)
}
