// SPDX-FileCopyrightText: 2023 Joern Barthel
// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import "fmt"

const (
	HMACSHA1   Algorithm = iota + 0x01 // HMAC with SHA-1
	HMACSHA256                         // HMAC with SHA-2 (256-bit)
	HMACSHA512                         // HMAC with SHA-2 (512-bit)
)

// Algorithm denotes the HMAc algorithm used for deriving the one-time passwords
type Algorithm byte

// String returns a string representation of the algorithm
func (a Algorithm) String() string {
	switch a {
	case HMACSHA1:
		return "HMAC-SHA1"
	case HMACSHA256:
		return "HMAC-SHA256"
	case HMACSHA512:
		return "HMAC-SHA512"
	default:
		return fmt.Sprintf("unknown %x", byte(a))
	}
}
