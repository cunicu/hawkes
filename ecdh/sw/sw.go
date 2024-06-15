// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

// Package sw implements ECDH in pure software / Go
package sw

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/katzenpost/nyquist/dh"

	ecdhx "cunicu.li/hawkes/ecdh"
)

var _ dh.Keypair = (*PrivateKey)(nil)

type PrivateKey struct {
	*ecdh.PrivateKey
}

type Config struct {
	Curve  ecdh.Curve
	Random io.Reader
}

func GeneratePrivateKey(cfg Config) (*PrivateKey, error) {
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}

	sc, err := cfg.Curve.GenerateKey(cfg.Random)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{sc}, nil
}

func LoadPrivateKey(cfg Config, k []byte) (*PrivateKey, error) {
	sk, err := cfg.Curve.NewPrivateKey(k)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{sk}, nil
}

func (kp *PrivateKey) UnmarshalBinary(data []byte) error {
	sk, err := kp.PrivateKey.Curve().NewPrivateKey(data)
	if err != nil {
		return err
	}

	kp.PrivateKey = sk

	return nil
}

func (kp *PrivateKey) Public() dh.PublicKey {
	return &ecdhx.PublicKey{
		PublicKey: kp.PrivateKey.Public().(*ecdh.PublicKey), //nolint:forcetypeassert
	}
}

func (kp *PrivateKey) DH(pk dh.PublicKey) ([]byte, error) {
	ecpk, ok := pk.(*ecdhx.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrInvalidPublicKeyType, pk)
	}

	return kp.PrivateKey.ECDH(ecpk.PublicKey)
}

func (kp *PrivateKey) DropPrivate() {
	kp.PrivateKey = nil
}

func (kp *PrivateKey) MarshalBinary() ([]byte, error) {
	return kp.PrivateKey.Bytes(), nil
}
