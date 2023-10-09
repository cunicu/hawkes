// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ecdh

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/katzenpost/nyquist/dh"
)

var _ dh.PublicKey = (*PublicKey)(nil)

var (
	ErrUnsupportedCurve = errors.New("unsupported curve")
	ErrUnmarshal        = errors.New("failed to unmarshal key")
)

type PublicKey struct {
	*ecdh.PublicKey
}

func (pk *PublicKey) MarshalText() ([]byte, error) {
	key, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	str := fmt.Sprintf("ecdh:%s:pk:%s", curveToName(pk.Curve()), base64.StdEncoding.EncodeToString(key))
	return []byte(str), nil
}

func (pk *PublicKey) UnmarshalText(text []byte) error {
	var curveName, keyStr string

	if n, err := fmt.Sscanf(string(text), "ecdh:%s:pk:%s", &curveName, &keyStr); err != nil {
		return fmt.Errorf("failed to parse: %w", err)
	} else if n != 1 {
		return fmt.Errorf("failed to parse")
	}

	curve := curveFromName(curveName)
	if curve == nil {
		return fmt.Errorf("unsupported curve: %s", curveName)
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("failed to parse: %w", err)
	}

	pk.PublicKey, err = curve.NewPublicKey(key)

	return err
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
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedCurve, pk.Curve())
	}

	x, y := elliptic.Unmarshal(curve, pk.Bytes())
	if x == nil {
		return nil, ErrUnmarshal
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

func curveFromName(name string) ecdh.Curve {
	switch name {
	case "secp256r1":
		return ecdh.P256()
	case "secp348r1":
		return ecdh.P384()
	case "secp512r1":
		return ecdh.P521()
	case "cv25519":
		return ecdh.X25519()
	}

	return nil
}

func curveToName(curve ecdh.Curve) string {
	switch curve {
	case ecdh.P256():
		return "secp256r1"
	case ecdh.P384():
		return "secp348r1"
	case ecdh.P521():
		return "secp512r1"
	case ecdh.X25519():
		return "cv25519"
	}

	return ""
}
