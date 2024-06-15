// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package handshake

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/katzenpost/nyquist"
	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/dh"
	"github.com/katzenpost/nyquist/hash"
	"github.com/katzenpost/nyquist/pattern"
)

//nolint:gochecknoglobals,unused
var protocol = nyquist.Protocol{
	Pattern: pattern.XX,
	Cipher:  cipher.ChaChaPoly,
	Hash:    hash.BLAKE2s,
}

var _ Handshake = (*NoiseHandshake)(nil)

type NoiseHandshake struct {
	*nyquist.HandshakeState
	cfg nyquist.HandshakeConfig

	rw io.ReadWriter
}

func NewNoiseHandshake(proto *nyquist.Protocol, ss dh.Keypair, sp dh.PublicKey, rw io.ReadWriter, initiator bool) (hs *NoiseHandshake, err error) {
	hs = &NoiseHandshake{
		rw: rw,
		cfg: nyquist.HandshakeConfig{
			DH: &nyquist.DHConfig{
				LocalStatic:  ss,
				RemoteStatic: sp,
			},
			IsInitiator: initiator,
			Protocol:    proto,
		},
	}

	if hs.HandshakeState, err = nyquist.NewHandshake(&hs.cfg); err != nil {
		return nil, fmt.Errorf("failed to create handshake: %w", err)
	}

	return hs, nil
}

func (hs *NoiseHandshake) Secret(_ context.Context) (ss Secret, err error) {
	for {
		var msg []byte

		if msg, err = hs.WriteMessage(nil, nil); err != nil {
			if errors.Is(err, nyquist.ErrDone) {
				break
			}

			return nil, fmt.Errorf("failed to write message: %w", err)
		}

		fmt.Printf("%p Pre-Write\n", hs)

		if _, err := hs.rw.Write(msg); err != nil {
			return nil, fmt.Errorf("failed to send message: %w", err)
		}

		fmt.Printf("%p Write: %s\n", hs, hex.EncodeToString(msg))

		fmt.Printf("%p Pre-Read\n", hs)

		msg = make([]byte, 1500)
		n, err := hs.rw.Read(msg)
		if err != nil {
			return nil, fmt.Errorf("failed to receive message: %w", err)
		}
		msg = msg[:n]

		fmt.Printf("%p Read: %s\n", hs, hex.EncodeToString(msg))

		if _, err = hs.ReadMessage(nil, msg); err != nil {
			if errors.Is(err, nyquist.ErrDone) {
				break
			}

			return nil, fmt.Errorf("failed to read message: %w", err)
		}
	}

	fmt.Printf("%p out", hs)

	return hs.GetStatus().HandshakeHash, nil
}
