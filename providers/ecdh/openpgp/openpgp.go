// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"errors"

	"cunicu.li/go-skes/providers/ecdh"

	"github.com/katzenpost/nyquist/dh"
)

// See: https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
// Based-on: https://git.sr.ht/~arx10/openpgpcard-x25519-agent

var errNotSupported = errors.New("not supported")

type Keypair struct {
	publicKey *ecdh.PublicKey
}

func (kp *Keypair) DH(pk dh.PublicKey) ([]byte, error) {
	return nil, nil // TODO
}

// DropPrivate discards the private key.
func (kp *Keypair) DropPrivate() {
	// Do nothing here as we want to keep the key on the token
}

// Public returns the public key of the keypair.
// func (kp *Keypair) Public() dh.PublicKey {
// 	pkECDH, err := kp.publicKey
// 	if err != nil {
// 		return nil
// 	}

// 	return &ecdh.PublicKey{
// 		PublicKey: pkECDH,
// 	}
// }

func (kp *Keypair) MarshalBinary() ([]byte, error) {
	return nil, errNotSupported
}

func (kp *Keypair) UnmarshalBinary(_ []byte) error {
	return errNotSupported
}

func (kp *Keypair) calculateSharedSecret(pk *ecdh.PublicKey) ([]byte, error) {
	// ctx, err := scard.EstablishContext()
	// if err != nil {
	// 	return nil, err
	// }

	// reader := ""

	// card, err := ctx.Connect(reader, scard.ShareExclusive, scard.ProtocolT1)

	return nil, nil
}
