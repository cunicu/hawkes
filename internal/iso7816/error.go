// SPDX-FileCopyrightText: 2023 Joern Barthel
// SPDX-License-Identifier: Apache-2.0

package iso7816

import (
	"bytes"
	"fmt"
)

// Code encapsulates (some) response codes from the spec
type Code []byte

// Error return the encapsulated error string
func (c Code) Error() string {
	if bytes.Equal(c, []byte{0x6a, 0x80}) {
		return "wrong syntax"
	} else if bytes.Equal(c, []byte{0x69, 0x84}) {
		return "no such object"
	}

	return fmt.Sprintf("unknown (% x)", []byte(c))
}

// IsMore indicates more data that needs to be fetched
func (c Code) IsMore() bool {
	return len(c) == 2 && c[0] == 0x61
}

// IsSuccess indicates that all data has been successfully fetched
func (c Code) IsSuccess() bool {
	return bytes.Equal([]byte{0x90, 0x00}, c)
}
