// SPDX-FileCopyrightText: 2023 Joern Barthel
// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
)

var errNoValuesFound = errors.New("no values found in response")

func (o *OATH) CalculateTOTP(name string) ([]byte, int, error) {
	var (
		challenge = make([]byte, 8)
		counter   = uint64(math.Floor(float64(o.Clock().Unix()) / o.Period.Seconds()))
	)

	binary.BigEndian.PutUint64(challenge, counter)

	log.Printf("Challenge ykoath: %s", hex.EncodeToString(challenge))

	return o.calculate(name, challenge, false)
}

func (o *OATH) CalculateHOTP(name string) ([]byte, int, error) {
	challenge := []byte{}

	return o.calculate(name, challenge, false)
}

// calculate implements the "CALCULATE" instruction
func (o *OATH) calculate(name string, challenge []byte, truncate bool) ([]byte, int, error) {
	var trunc byte
	if truncate {
		trunc = 0x01
	}

	res, err := o.send(0x00, insCalculate, 0x00, trunc,
		write(tagName, []byte(name)),
		write(tagChallenge, challenge),
	)
	if err != nil {
		return nil, 0, err
	}

	for _, tv := range res {
		switch tv.tag {

		case tagResponse, tagTruncated:
			digits := int(tv.value[0])
			hash := tv.value[1:]
			return hash, digits, nil

		default:
			return nil, 0, fmt.Errorf(errUnknownTag, tv.tag)
		}
	}

	return nil, 0, fmt.Errorf("%w: %x", errNoValuesFound, res)
}
