// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
)

//nolint:unused
type pivSlotRef struct {
	SerialNo int `koanf:"serial_no"`
	Slot     int `koanf:"slot"`
}

//nolint:unused
func (s *pivSlotRef) MarshalText() (text []byte, err error) {
	str := fmt.Sprintf("ecdh:%s:sk:piv:%d:%d", "Secp256r1", s.SerialNo, s.Slot)
	return []byte(str), nil
}

//nolint:unused
func (s *pivSlotRef) UnmarshalText(text []byte) error {
	var curve string
	if n, err := fmt.Sscanf(string(text), "ecdh:%s:sk:piv:%d:%d", &curve, &s.SerialNo, &s.Slot); err != nil {
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

// var _ Provider = (*pivProvider)(nil)

// type pivProvider struct{}

// //nolint:gochecknoinits
// func init() {
// 	Register("PIV", &pivProvider{})
// }
