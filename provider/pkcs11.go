// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
)

//nolint:unused
type pkcs11SlotRef struct {
	Slot   int    `koanf:"slot"`
	Module string `koanf:"module"`
}

//nolint:unused
func (s *pkcs11SlotRef) MarshalText() (text []byte, err error) {
	str := fmt.Sprintf("ecdh:%s:sk:pkcs11:%s:%d", "Secp256r1", s.Module, s.Slot)
	return []byte(str), nil
}

//nolint:unused
func (s *pkcs11SlotRef) UnmarshalText(text []byte) error {
	var curve string
	if n, err := fmt.Sscanf(string(text), "ecdh:%s:sk:pkcs11:%s:%d", &curve, &s.Module, &s.Slot); err != nil {
		return fmt.Errorf("%w: %w", ErrParse, err)
	} else if n != 3 {
		return ErrParse
	}

	switch curve {
	case "Secp256r1":
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedCurve, curve)
	}

	return nil
}

// var _ Provider = (*pkcs11Provider)(nil)

// type pkcs11Provider struct{}

// //nolint:gochecknoinits
// func init() {
// 	Register("PKCS11", &pkcs11Provider{})
// }
