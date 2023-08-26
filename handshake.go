// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package skes

import (
	"context"
	"fmt"

	"github.com/katzenpost/nyquist"
	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/dh"
	"github.com/katzenpost/nyquist/hash"
	"github.com/katzenpost/nyquist/pattern"
)

var _ Provider = (*Handshake)(nil)

var protocol = &nyquist.Protocol{
	Pattern: pattern.XX,
	DH:      dh.X25519,
	Cipher:  cipher.ChaChaPoly,
	Hash:    hash.BLAKE2s,
}

type Handshake struct {
	state *nyquist.HandshakeState

	dh dh.DH
}

func NewHandshake(dh dh.DH) (hs *Handshake, err error) {
	hs = &Handshake{
		dh: dh,
	}

	cfg := &nyquist.HandshakeConfig{
		Protocol: protocol,
	}

	if hs.state, err = nyquist.NewHandshake(cfg); err != nil {
		return nil, fmt.Errorf("failed to create handshake: %w", err)
	}

	return hs, nil
}

func (hs *Handshake) Secret(ctx context.Context) (Secret, error) {
	hs.state.GetStatus()

	return Secret{}, nil
}
