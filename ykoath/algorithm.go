// SPDX-FileCopyrightText: 2023 Joern Barthel
// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import "fmt"

const (
	HMAC_SHA1   Algorithm = iota + 0x01 // HMAC with SHA-1
	HMAC_SHA256                         // HMAC with SHA-2 (256-bit)
	HMAC_SHA512                         // HMAC with SHA-2 (512-bit)
)

// Algorithm denotes the HMAc algorithm used for deriving the one-time passwords
type Algorithm byte

// String returns a string representation of the algorithm
func (a Algorithm) String() string {
	switch a {
	case HMAC_SHA1:
		return "HMAC-SHA1"
	case HMAC_SHA256:
		return "HMAC-SHA256"
	case HMAC_SHA512:
		return "HMAC-SHA512"
	default:
		return fmt.Sprintf("unknown %x", byte(a))
	}
}
