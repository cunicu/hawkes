// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package sw

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"

	"github.com/katzenpost/nyquist/dh"

	ecdhx "cunicu.li/hawkes/ecdh"
)

//nolint:gochecknoglobals
var (
	P256 = &DH{ecdh.P256()}
	P384 = &DH{ecdh.P384()}
	P521 = &DH{ecdh.P521()}

	ErrInvalidPublicKeyType = errors.New("invalid public key type")
)

var _ dh.DH = (*DH)(nil)

type DH struct {
	curve ecdh.Curve
}

func (dh *DH) String() string {
	return fmt.Sprint(dh.curve)
}

func (dh *DH) GenerateKeypair(rng io.Reader) (dh.Keypair, error) {
	return GeneratePrivateKey(Config{
		Curve:  dh.curve,
		Random: rng,
	})
}

func (dh *DH) ParsePrivateKey(data []byte) (dh.Keypair, error) {
	sk, err := dh.curve.NewPrivateKey(data)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{sk}, nil
}

func (dh *DH) ParsePublicKey(data []byte) (dh.PublicKey, error) {
	pk, err := dh.curve.NewPublicKey(data)
	if err != nil {
		return nil, err
	}

	return &ecdhx.PublicKey{
		PublicKey: pk,
	}, nil
}

func (dh *DH) Size() (l int) {
	return curveSize(dh.curve) + 1
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
