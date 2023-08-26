// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ecdh

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"

	"github.com/katzenpost/nyquist/dh"
)

//nolint:gochecknoglobals
var (
	P256 = &DH{ecdh.P256()}
	P384 = &DH{ecdh.P384()}
	P521 = &DH{ecdh.P521()}

	errInvalidPublicKeyType = errors.New("invalid public key type")
)

type DH struct {
	curve ecdh.Curve
}

func (dh *DH) String() string {
	return fmt.Sprint(dh.curve)
}

func (dh *DH) GenerateKeypair(rng io.Reader) (dh.Keypair, error) {
	sc, err := dh.curve.GenerateKey(rng)
	if err != nil {
		return nil, err
	}

	return &Keypair{sc}, nil
}

func (dh *DH) ParsePrivateKey(data []byte) (dh.Keypair, error) {
	sk, err := dh.curve.NewPrivateKey(data)
	if err != nil {
		return nil, err
	}

	return &Keypair{sk}, nil
}

func (dh *DH) ParsePublicKey(data []byte) (dh.PublicKey, error) {
	pk, err := dh.curve.NewPublicKey(data)
	if err != nil {
		return nil, err
	}

	return &PublicKey{pk}, nil
}

func (dh *DH) Size() (l int) {
	return curveSize(dh.curve) + 1
}

var _ dh.Keypair = (*Keypair)(nil)

type Keypair struct {
	*ecdh.PrivateKey
}

func (kp *Keypair) UnmarshalBinary(data []byte) error {
	sk, err := kp.PrivateKey.Curve().NewPrivateKey(data)
	if err != nil {
		return err
	}

	kp.PrivateKey = sk

	return nil
}

func (kp *Keypair) Public() dh.PublicKey {
	ecpk := kp.PrivateKey.Public().(*ecdh.PublicKey) //nolint:forcetypeassert
	return &PublicKey{
		ecpk,
	}
}

func (kp *Keypair) DH(pk dh.PublicKey) ([]byte, error) {
	ecpk, ok := pk.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %T", errInvalidPublicKeyType, pk)
	}

	return kp.PrivateKey.ECDH(ecpk.PublicKey)
}

func (kp *Keypair) DropPrivate() {
	kp.PrivateKey = nil
}

func (kp *Keypair) MarshalBinary() ([]byte, error) {
	return kp.PrivateKey.Bytes(), nil
}

var _ dh.PublicKey = (*PublicKey)(nil)

type PublicKey struct {
	*ecdh.PublicKey
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.Bytes(), nil
}

func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	curve := pk.PublicKey.Curve()
	ecpk, err := curve.NewPublicKey(data)
	if err != nil {
		return err
	}

	pk.PublicKey = ecpk

	return nil
}

func (pk *PublicKey) ECDSA() (*ecdsa.PublicKey, error) {
	curve := ellipticCurve(pk.Curve())
	if curve == nil {
		return nil, fmt.Errorf("unsupported curve: %v", pk.Curve())
	}

	x, y := elliptic.Unmarshal(curve, pk.Bytes())
	if x == nil {
		return nil, errors.New("failed to unmarshal key")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func ellipticCurve(curve ecdh.Curve) elliptic.Curve {
	switch curve {
	case ecdh.P256():
		return elliptic.P256()
	case ecdh.P384():
		return elliptic.P384()
	case ecdh.P521():
		return elliptic.P521()
	}

	return nil
}

func curveSize(curve ecdh.Curve) (l int) {
	switch curve {
	case ecdh.P256():
		l = 256
	case ecdh.P384():
		l = 348
	case ecdh.P521():
		l = 521
	}

	return (l + 7) / 8
}

//nolint:gochecknoinits
func init() {
	dh.Register(P256)
	dh.Register(P384)
	dh.Register(P521)
}
