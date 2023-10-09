// SPDX-FileCopyrightText: 2023 Steffen Vogel
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/ebfe/scard"
	"github.com/stretchr/testify/require"
)

func TestYKOATH(t *testing.T) {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slog.SetDefault(slog.New(handler))

	require := require.New(t)

	ctx, err := scard.EstablishContext()
	require.NoError(err)

	defer func() {
		err := ctx.Release()
		require.NoError(err)
	}()

	card, err := connectFirstCard(ctx, isYubikey)
	require.NoError(err)

	defer func() {
		err := card.Disconnect(scard.LeaveCard)
		require.NoError(err)
	}()

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
}

func isYubikey(s string) bool {
	return strings.Contains(s, "YubiKey")
}

func connectFirstCard(ctx *scard.Context, filter func(string) bool) (*scard.Card, error) {
	readers, err := ctx.ListReaders()
	if err != nil {
		return nil, err
	}

	for _, reader := range readers {
		if !filter(reader) {
			continue
		}

		card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
		if err != nil {
			return nil, err
		}

		return card, nil
	}

	return nil, errors.New("no such card exists")
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
