// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package se

import (
	"io"

	"github.com/katzenpost/nyquist/dh"
)

var _ dh.DH = (*DH)(nil)

type DH struct{}

func (dh *DH) String() string {
	return "piv" // + dh.hash?
}

// GenerateKeypair generates a new Diffie-Hellman keypair using the
// provided entropy source.
func (dh *DH) GenerateKeypair(rng io.Reader) (dh.Keypair, error) {
	return nil, nil
}

// ParsePrivateKey parses a binary encoded private key.
func (dh *DH) ParsePrivateKey(data []byte) (dh.Keypair, error) {
	return nil, nil
}

// ParsePublicKey parses a binary encoded public key.
func (dh *DH) ParsePublicKey(data []byte) (dh.PublicKey, error) {
	return nil, nil
}

// Size returns the size of public keys and DH outputs in bytes (`DHLEN`).
func (dh *DH) Size() int {
	return 0
}

var _ dh.Keypair = (*KeyPair)(nil)

type KeyPair struct{}

// DropPrivate discards the private key.
func (kp *KeyPair) DropPrivate() {
}

// Public returns the public key of the keypair.
func (kp *KeyPair) Public() dh.PublicKey

// DH performs a Diffie-Hellman calculation between the private key
// in the keypair and the provided public key.
func (kp *KeyPair) DH(publicKey dh.PublicKey) ([]byte, error)

func (kp *KeyPair) MarshalBinary() (data []byte, err error) {
	return nil, nil
}

func (kp *KeyPair) UnmarshalBinary(data []byte) error {
	return nil
}

var _ dh.PublicKey = (*PublicKey)(nil)

// PublicKey is a Diffie-Hellman public key.
type PublicKey struct{}

// Bytes returns the binary serialized public key.
//
// Warning: Altering the returned slice is unsupported and will lead
// to unexpected behavior.
func (pk *PublicKey) Bytes() []byte {
	return nil
}

func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	return nil, nil
}

func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	return nil
}
