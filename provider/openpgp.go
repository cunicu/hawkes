// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
)

//nolint:unused
type openpgpSlotRef struct {
	SerialNo int `koanf:"serial_no"`
	Slot     int `koanf:"slot"`
}

//nolint:unused
func (s *openpgpSlotRef) MarshalText() (text []byte, err error) {
	str := fmt.Sprintf("ecdh:%s:sk:openpgp:%d:%d", "Secp256r1", s.SerialNo, s.Slot)
	return []byte(str), nil
}

//nolint:unused
func (s *openpgpSlotRef) UnmarshalText(text []byte) error {
	var curve string
	if n, err := fmt.Sscanf(string(text), "ecdh:%s:sk:openpgp:%d:%d", &curve, &s.SerialNo, &s.Slot); err != nil {
		return fmt.Errorf("%w: %w", ErrParse, err)
	} else if n != 3 {
		return ErrParse
	}

	switch curve {
	case "Secp256r1": //nolint:goconst
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedCurve, curve)
	}

	return nil
}

// var _ Provider = (*openpgpProvider)(nil)

// type openpgpProvider struct{}

// //nolint:gochecknoinits
// func init() {
// 	Register("OpenPGP", &openpgpProvider{})
// }
