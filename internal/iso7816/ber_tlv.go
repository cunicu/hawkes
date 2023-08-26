// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package iso7816

import (
	"errors"
	"fmt"
)

var (
	errInvalidTag    = fmt.Errorf("invalid tag")
	errInvalidLength = errors.New("invalid length")
)

func EncodeTLV(t Tag, data []byte) (b []byte) {
	if len(data) > 0x7f {
		panic("long form length encoding not supported")
	}

	b = t.Bytes()
	b = append(b, byte(len(data)))
	b = append(b, data...)

	return b
}

func DecodeTag(b []byte) (Tag, []byte) {
	// ISO 7816-4 Section 5.2.2.1 BER-TLV tag fields
	switch {
	case b[0]&0x1f != 0x1f:
		return Tag(b[0]), b[1:]
	case b[1]&0x80 == 0 && b[1]&0x7f > 30:
		return Tag(uint32(b[0])<<8 | uint32(b[1])), b[2:]
	case b[1]&0x80 == 0x80 && b[1]&0x7f != 0:
		return Tag(uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[0])), b[3:]
	}

	return 0, nil
}

func DecodeLength(b []byte) (int, []byte, error) {
	// Short form
	if b[0] <= 0x7f {
		return int(b[0]), b[1:], nil
	}

	// Long form
	n := int(b[0] & 0x7f)
	if len(b) < n+1 {
		return -1, nil, errInvalidLength
	}

	l := 0
	for i := 1; i <= n; i++ {
		l <<= 8
		l |= int(b[i])
	}

	return l, b[n+1:], nil
}

func DecodeTLV(b []byte) (t Tag, v, c []byte, err error) {
	var l int

	if t, b = DecodeTag(b); t == TagInvalid {
		return 0, nil, nil, errInvalidTag
	}

	if l, b, err = DecodeLength(b); err != nil {
		return 0, nil, nil, err
	}

	return t, b[:l], b[l:], nil
}

func DecodeCompactTLV(b []byte) (t CompactTag, v, c []byte, err error) {
	if len(b) < 1 {
		return 0, nil, nil, errInvalidLength
	}

	t = CompactTag(b[0] >> 4)
	l := b[0] & 0xf

	return t, v[1 : 1+l], v[1+l:], nil
}
