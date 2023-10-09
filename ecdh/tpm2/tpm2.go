// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

// Package tpm2 provides an ECDH implementation backed by a TPM2 module.
package tpm2

import (
	"errors"

	"github.com/katzenpost/nyquist/dh"

	"cunicu.li/hawkes/ecdh"
)

// https://github.com/Foxboron/tpm-stuff/blob/master/ecc_keys/keys_test.go

var _ ecdh.PrivateKey = (*PrivateKey)(nil)

type PrivateKey struct{}

// Public returns the public key of the keypair.
func (kp *PrivateKey) Public() (pk dh.PublicKey) {
	return pk
}

// DH performs a Diffie-Hellman calculation between the private key
// in the keypair and the provided public key.
func (kp *PrivateKey) DH(_ dh.PublicKey) ([]byte, error) {
	return nil, errors.ErrUnsupported
}
