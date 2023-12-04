// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp_test

import (
	"os"
	"testing"

	"github.com/ebfe/scard"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"cunicu.li/hawkes/internal/openpgp"
)

func TestCard(t *testing.T) {
	require := require.New(t)

	ctx, err := scard.EstablishContext()
	require.NoError(err)

	readers, err := ctx.ListReaders()
	require.NoError(err)
	require.True(len(readers) >= 1)

	sc, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolAny)
	require.NoError(err)

	card, err := openpgp.NewCard(sc)
	require.NoError(err)

	// ar, err := card.GetApplicationRelatedData()
	// require.NoError(err)

	// err = yaml.NewEncoder(os.Stdout).Encode(&ar)
	// require.NoError(err)

	// ch, err := card.GetCardholder()
	// require.NoError(err)

	// err = yaml.NewEncoder(os.Stdout).Encode(&ch)
	// require.NoError(err)

	// sts, err := sc.Status()
	// require.NoError(err)

	// log.Printf("Card status: %+#v\n", sts)

	// rnd, err := card.GetChallenge(16)
	// require.NoError(err)

	// t.Logf("Data: %s", hex.EncodeToString(rnd))

	sst, err := card.GetSecuritySupportTemplate()
	require.NoError(err)

	err = yaml.NewEncoder(os.Stdout).Encode(&sst)
	require.NoError(err)

	err = sc.Disconnect(scard.ResetCard)
	require.NoError(err)
}
