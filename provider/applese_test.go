// SPDX-FileCopyrightText: 2023 Steffen Vogel
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppleSE(t *testing.T) {
	require := require.New(t)

	p1, err := newAppleSecureEnclaveProvider()
	require.NoError(err)

	p2, err := newFileProvider()
	require.NoError(err)

	keys, err := p1.Keys()
	require.NoError(err)

	for _, key := range keys {
		t.Logf("Key: %s", key)
	}

	id1, err := p1.CreateKey("test1")
	require.NoError(err)
	require.NotNil(id1)

	defer func() {
		err := p1.DestroyKey(id1)
		require.NoError(err)
	}()

	id2, err := p2.CreateKey("test1")
	require.NoError(err)
	require.NotNil(id2)

	defer func() {
		err := p2.DestroyKey(id2)
		require.NoError(err)
	}()

	key1, err := p1.OpenKey(id1)
	require.NoError(err)
	require.Equal(key1.ID(), id1)

	defer func() {
		err := key1.Close()
		require.NoError(err)
	}()

	key2, err := p2.OpenKey(id2)
	require.NoError(err)
	require.Equal(key2.ID(), id2)

	defer func() {
		err := key2.Close()
		require.NoError(err)
	}()

	key1DH, ok := key1.(PrivateKeyDH)
	require.True(ok)

	key2DH, ok := key2.(PrivateKeyDH)
	require.True(ok)

	ss1, err := key1DH.DH(key2DH.Public())
	require.NoError(err)

	ss2, err := key2DH.DH(key1DH.Public())
	require.NoError(err)

	require.Equal(ss1, ss2)
}
