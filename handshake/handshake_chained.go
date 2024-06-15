// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package handshake

import (
	"context"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/errgroup"
)

type ChainedHandshake []Handshake

func NewChainedHandshake(slots ...Handshake) ChainedHandshake {
	chs := ChainedHandshake{}

	for _, s := range slots {
		chs = append(chs, s)
	}

	return chs
}

func (cp ChainedHandshake) Secret(ctx context.Context) (s Secret, err error) {
	group, ctx := errgroup.WithContext(ctx)
	res := make([]Secret, len(cp))

	for i, p := range cp {
		i := i
		p := p

		group.Go(func() (err error) {
			res[i], err = p.Secret(ctx)
			return err
		})
	}

	if err := group.Wait(); err != nil {
		return s, err
	}

	for _, t := range res {
		s.mix(t[:])
	}

	return s, nil
}

// blake2 calculates the BLAKE2B digest over the provided data and key
func blake2(k Secret, d []byte) Secret {
	h, _ := blake2b.New256(k[:])
	h.Write(d)
	return Secret(h.Sum(nil))
}

// hmac calculates an HMAC using BLAKE2B as its inner hashing function
func hmac(k Secret, d []byte) Secret {
	var iKey, oKey Secret
	for i := range iKey {
		iKey[i] = k[i] ^ 0x36
		oKey[i] = k[i] ^ 0x5c
	}

	outer := blake2(iKey, d)
	return blake2(oKey, outer[:])
}

// A keyed hmac function with one 32-byte input, one variable-size input, and one 32-byte output.
// As keyed hmac function we use the HMAC construction with BLAKE2s as the inner hmac function.
func (k Secret) hash(data ...[]byte) Secret {
	for _, d := range data {
		k = hmac(k, d)
	}
	return k
}

// mix calculates a chained hash using HMAC-BLAKE2B
func (k Secret) mix(data ...[]byte) Secret {
	for _, d := range data {
		k = k.hash(d)
	}
	return k
}
