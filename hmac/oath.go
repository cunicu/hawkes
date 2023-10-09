// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package sw

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"log"
	"math"
	"time"
)

type OATH struct {
	Hash   func() hash.Hash
	Period time.Duration

	key []byte
}

func New(key []byte, hash func() hash.Hash, period time.Duration) (*OATH, error) {
	return &OATH{
		Hash:   hash,
		Period: period,
		key:    key,
	}, nil
}

func (o *OATH) CalculateTOTP(t time.Time) []byte {
	counter := uint64(math.Floor(float64(t.Unix()) / o.Period.Seconds()))
	return o.CalculateHOTP(counter)
}

func (o *OATH) ValidateTOTP(t time.Time, hash []byte) bool {
	hash2 := o.CalculateTOTP(t)
	return subtle.ConstantTimeCompare(hash2, hash) == 0
}

func (o *OATH) CalculateHOTP(counter uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	log.Printf("Challenge oath: %s", hex.EncodeToString(buf))

	mac := hmac.New(o.Hash, o.key)
	mac.Write(buf)
	return mac.Sum(nil)
}

func (o *OATH) ValidateHOTP(counter uint64, hash []byte) bool {
	hash2 := o.CalculateHOTP(counter)
	return subtle.ConstantTimeCompare(hash2, hash) == 0
}
