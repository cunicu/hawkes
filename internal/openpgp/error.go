// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import "fmt"

//nolint:gochecknoglobals
var statusCodes = map[uint16]string{
	0x6285: "in termination state",
	0x640E: "out of memory",
	0x6581: "memory failure",
	0x6600: "security-related issues",
	0x6700: "wrong length",
	0x6881: "logical channel not supported",
	0x6882: "secure messaging not supported",
	0x6883: "last command of chain expected",
	0x6884: "command chaining not supported",
	0x6982: "security status not satisfied",
	0x6983: "authentication method blocked",
	0x6985: "condition of use not satisfied",
	0x6987: "expected secure messaging data objects missing",
	0x6988: "secure messaging data objects incorrect",
	0x6A80: "incorrect parameters in the command",
	0x6A82: "file not found",
	0x6A88: "data object not found",
	0x6B00: "wrong parameters",
	0x6D00: "instruction code not supported",
	0x6E00: "class not supported",
	0x6F00: "no precise diagnosis",
	0x9000: "command correct",
}

type Error uint16

func (e Error) Error() string {
	if e&0x63C0 == 0x63C0 {
		return fmt.Sprintf("password not checked: %d tries left", e&0xf)
	}

	str, ok := statusCodes[uint16(e)]
	if !ok {
		return "unknown error"
	}

	return str
}
