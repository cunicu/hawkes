// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package handshake

import (
	"context"
	"encoding/binary"
	"math"
	"time"

	"cunicu.li/hawkes/provider"
)

var _ Handshake = (*OATHHandshake)(nil)

type OATHHandshake struct {
	Timestep time.Duration
	Key      provider.PrivateKeyHMAC
	Clock    func() time.Time
}

func (hs *OATHHandshake) Secret(_ context.Context) (ss Secret, err error) {
	return hs.calculateTOTP(hs.Clock())
}

func (hs *OATHHandshake) calculateTOTP(t time.Time) ([]byte, error) {
	counter := uint64(math.Floor(float64(t.Unix()) / hs.Timestep.Seconds()))
	return hs.calculateHOTP(counter)
}

func (hs *OATHHandshake) calculateHOTP(counter uint64) ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	return hs.Key.HMAC(buf)
}
