// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ecdh

import (
	"errors"

	"github.com/katzenpost/nyquist/dh"
)

type PrivateKey interface {
	DH(pk dh.PublicKey) ([]byte, error)
	Public() dh.PublicKey
}

type InMemoryPrivateKey interface {
	// Zero-ize the secret in memory
	Drop()
}

var _ dh.Keypair = (*StaticKeypair)(nil)

type StaticKeypair struct {
	PrivateKey
}

func (kp *StaticKeypair) DropPrivate() {
	if mkp, ok := kp.PrivateKey.(InMemoryPrivateKey); ok {
		mkp.Drop()
	}
}

func (kp *StaticKeypair) MarshalBinary() ([]byte, error) {
	return nil, errors.ErrUnsupported
}

func (kp *StaticKeypair) UnmarshalBinary([]byte) error {
	return errors.ErrUnsupported
}
