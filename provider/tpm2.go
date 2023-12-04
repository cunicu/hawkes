// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
)

//nolint:unused
type tpm2SlotRef struct {
	Device string `koanf:"device"`
}

//nolint:unused
func (s *tpm2SlotRef) MarshalText() (text []byte, err error) {
	str := fmt.Sprintf("ecdh:%s:sk:tpm2:%s", "Secp256r1", s.Device)
	return []byte(str), nil
}

//nolint:unused
func (s *tpm2SlotRef) UnmarshalText(text []byte) (err error) {
	var curve string
	if n, err := fmt.Sscanf(string(text), "ecdh:%s:sk:tpm2:%s", &curve, &s.Device); err != nil {
		return fmt.Errorf("%w: %w", ErrParse, err)
	} else if n != 2 {
		return ErrParse
	}

	switch curve {
	case "Secp256r1":
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedCurve, curve)
	}

	return nil
}

// var _ Provider = (*tpm2Provider)(nil)

// type tpm2Provider struct{}

// //nolint:gochecknoinits
// func init() {
// 	Register("TPM2", &tpm2Provider{})
// }
