// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package iso7816

type (
	CompactTag byte   // As used in compact TLV encoding
	Tag        uint32 // in theory ISO 7816-4 also supports 3-byte tags
)

const (
	TagInvalid Tag = 0
)

func (t Tag) Bytes() []byte {
	switch t.Size() {
	case 1:
		return []byte{byte(t >> 0)}
	case 2:
		return []byte{byte(t >> 8), byte(t >> 0)}
	case 3:
		return []byte{byte(t >> 16), byte(t >> 8), byte(t >> 0)}
	case 4:
		return []byte{byte(t >> 24), byte(t >> 16), byte(t >> 8), byte(t >> 0)}
	}

	return nil
}

func (t Tag) IsConstructed() bool {
	return t.Bytes()[0]&(1<<5) != 0
}

func (t Tag) Size() int {
	switch {
	case t>>8 == 0:
		return 1
	case t>>16 == 0:
		return 2
	case t>>24 == 0:
		return 3
	}
	return 4
}
