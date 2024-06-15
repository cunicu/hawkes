// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

// Package openpgp provides an ECDH implementation backed by an OpenPGP card.
package openpgp

import (
	"github.com/katzenpost/nyquist/dh"

	"cunicu.li/hawkes/ecdh"
)

// See: https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
// Based-on: https://git.sr.ht/~arx10/openpgpcard-x25519-agent

var _ ecdh.PrivateKey = (*PrivateKey)(nil)

type PrivateKey struct {
	//nolint:unused
	publicKey *ecdh.PublicKey
}

func (kp *PrivateKey) DH(_ dh.PublicKey) ([]byte, error) {
	// ctx, err := scard.EstablishContext()
	// if err != nil {
	// 	return nil, err
	// }

	// reader := ""

	// card, err := ctx.Connect(reader, scard.ShareExclusive, scard.ProtocolT1)

	return nil, nil // TODO
}

// Public returns the public key of the keypair.
func (kp *PrivateKey) Public() (pk dh.PublicKey) {
	return pk
}
