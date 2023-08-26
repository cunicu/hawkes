// SPDX-FileCopyrightText: 2023 Joern Barthel
// SPDX-License-Identifier: Apache-2.0

package yk

import "fmt"

const (
	HOTP Type = 0x10 // HMAC based one-time passwords (https://tools.ietf.org/html/rfc4226)
	TOTP Type = 0x20 // Time-based one-time passwords (https://tools.ietf.org/html/rfc6238)
)

// Type denotes the kind of derivation used for the one-time password
type Type byte

// String returns a string representation of the type
func (t Type) String() string {
	switch t {
	case HOTP:
		return "HOTP"
	case TOTP:
		return "TOTP"
	default:
		return fmt.Sprintf("unknown %x", byte(t))
	}
}
