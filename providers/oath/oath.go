// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package oath

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
	Clock  func() time.Time
	Period time.Duration

	key []byte
}

func New(key []byte, hash func() hash.Hash) (*OATH, error) {
	return &OATH{
		Hash:   hash,
		Clock:  time.Now,
		Period: 30 * time.Second,
		key:    key,
	}, nil
}

func (o *OATH) CalculateTOTP() []byte {
	counter := uint64(math.Floor(float64(o.Clock().Unix()) / o.Period.Seconds()))
	return o.CalculateHOTP(counter)
}

func (o *OATH) ValidateTOTP(hash []byte) bool {
	hash2 := o.CalculateTOTP()
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
