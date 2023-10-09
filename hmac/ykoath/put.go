// SPDX-FileCopyrightText: 2023 Joern Barthel
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

var errNameTooLong = errors.New("name too long")

// Put sends a "PUT" instruction, storing a new / overwriting an existing OATH
// credentials with an algorithm and type, 6 or 8 digits one-time password,
// shared secrets and touch-required bit
func (o *OATH) Put(name string, alg Algorithm, typ Type, key []byte, touch bool, digits int) error {
	if l := len(name); l > 64 {
		return fmt.Errorf("%w  (%d > 64)", errNameTooLong, l)
	}

	var h hash.Hash
	switch alg {
	case HMACSHA1:
		h = sha1.New() //nolint:gosec
	case HMACSHA256:
		h = sha256.New()
	case HMACSHA512:
		h = sha512.New()
	}

	if len(key) > h.Size() {
		h.Write(key)
		key = h.Sum(nil)
	}

	var (
		algType = (0xf0|byte(alg))&0x0f | byte(typ)
		prp     []byte
	)

	if touch {
		prp = write(tagProperty, []byte{0x02})
	}

	if typ == HOTP {
		ctr := make([]byte, 4)
		binary.BigEndian.PutUint32(ctr, 0)

		prp = append(prp,
			write(tagImf, ctr)...,
		)
	}

	_, err := o.send(0x00, insPut, 0x00, 0x00,
		write(tagName, []byte(name)),
		write(tagKey, []byte{algType, byte(digits)}, key),
		prp,
	)

	return err
}
