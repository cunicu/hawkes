// SPDX-FileCopyrightText: 2023 Steffen Vogel
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/rand"
	"log/slog"
	"os"
	"testing"

	"cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/filter"
	"cunicu.li/go-iso7816/test"
	"cunicu.li/go-ykoath/v2"
	"github.com/stretchr/testify/require"
)

func TestYKOATH(t *testing.T) {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slog.SetDefault(slog.New(handler))

	withCard(t, func(t *testing.T, card *iso7816.Card) {
		require := require.New(t)

		p1, err := newYKOATHProvider(card)
		require.NoError(err)

		p2, err := newFileProvider()
		require.NoError(err)

		ykp, ok := p1.(*ykoathProvider)
		require.True(ok)

		mp, ok := p2.(*fileProvider)
		require.True(ok)

		keys, err := p1.Keys()
		require.NoError(err)
		require.Empty(keys)

		secret, err := generateSecret()
		require.NoError(err)

		id1, err := ykp.CreateKeyFromSecret("test1", secret)
		require.NoError(err)
		require.NotNil(id1)

		defer func() {
			err := p1.DestroyKey(id1)
			require.NoError(err)

			keys, err = p1.Keys()
			require.NoError(err)
			require.Empty(keys)
		}()

		id2, err := mp.CreateKeyFromSecret("test1", secret)
		require.NoError(err)
		require.NotNil(id2)

		defer func() {
			err := p2.DestroyKey(id2)
			require.NoError(err)

			keys, err = p2.Keys()
			require.NoError(err)
			require.Empty(keys)
		}()

		keys, err = p1.Keys()
		require.NoError(err)
		require.Len(keys, 1)
		require.Equal(keys[0], id1)

		key1, err := p1.OpenKey(id1)
		require.NoError(err)
		require.Equal(key1.ID(), id1)

		defer func() {
			err = key1.Close()
			require.NoError(err)
		}()

		key2, err := p2.OpenKey(id2)
		require.NoError(err)
		require.Equal(key2.ID(), id2)

		defer func() {
			err = key2.Close()
			require.NoError(err)
		}()

		key1HMAC, ok := key1.(PrivateKeyHMAC)
		require.True(ok)

		key2HMAC, ok := key2.(PrivateKeyHMAC)
		require.True(ok)

		challenge := []byte("1234")

		ss1, err := key1HMAC.HMAC(challenge)
		require.NoError(err)

		ss2, err := key2HMAC.HMAC(challenge)
		require.NoError(err)

		require.Equal(ss1, ss2)
	})
}

func generateSecret() ([]byte, error) {
	// RFC4226 recommends a secret length of 160bits
	// but we use 256bits for compatibility with P256 private keys
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func withCard(t *testing.T, cb func(t *testing.T, card *iso7816.Card)) {
	test.WithCard(t, filter.IsYubiKey, func(t *testing.T, card *iso7816.Card) {
		require := require.New(t)

		ykCard, err := ykoath.NewCard(card)
		require.NoError(err)

		_, err = ykCard.Select()
		require.NoError(err)

		err = ykCard.Reset()
		require.NoError(err)

		cb(t, card)
	})
}
