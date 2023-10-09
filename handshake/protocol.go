// SPDX-FileCopyrightText: 2023 Steffen Vogel
// SPDX-License-Identifier: Apache-2.0

package handshake

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/katzenpost/nyquist"
	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/dh"
	"github.com/katzenpost/nyquist/hash"
	"github.com/katzenpost/nyquist/pattern"
)

var ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")

var DefaultOathTotpProtocol = &OathTotpProtocol{
	Hash:     hash.SHA256,
	Timestep: time.Minute,
}

var WireGuardProtocol = &nyquist.Protocol{
	Pattern: pattern.IK,
	DH:      dh.X25519,
	Cipher:  cipher.ChaChaPoly,
	Hash:    hash.BLAKE2s,
}

type Protocol interface {
	String() string
}

type OathHotpProtocol struct {
	Hash hash.Hash
}

func (c *OathHotpProtocol) String() string {
	return fmt.Sprintf("OATH-HOTP_%s", c.Hash)
}

type OathTotpProtocol struct {
	Timestep time.Duration
	Hash     hash.Hash
}

func (c *OathTotpProtocol) String() string {
	return fmt.Sprintf("OATH-TOTP_%s_%s", c.Hash, c.Timestep)
}

func ParseProtocol(s string) (Protocol, error) {
	parts := strings.Split(s, "_")

	switch parts[0] {
	case "OATH-HOTP":
		if len(parts) < 2 {
			return nil, ErrParse
		}

		hash := hash.FromString(parts[1])
		if hash == nil {
			return nil, ErrUnsupportedHashAlgorithm
		}

		return &OathHotpProtocol{
			Hash: hash,
		}, nil

	case "OATH-TOTP":
		if len(parts) < 3 {
			return nil, ErrParse
		}

		hash := hash.FromString(parts[1])
		if hash == nil {
			return nil, ErrUnsupportedHashAlgorithm
		}

		timestep, err := time.ParseDuration(parts[2])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrParse, err)
		}

		c := &OathTotpProtocol{
			Hash:     hash,
			Timestep: timestep,
		}

		return c, nil

	case "WireGuard":
		return WireGuardProtocol, nil

	case "Noise":
		return nyquist.NewProtocol(s)
	}

	return nil, fmt.Errorf("%w: unknown protocol type", ErrParse)
}

func getStr(m map[string]any, k string) (string, bool) {
	a, ok := m[k]
	if !ok {
		return "", false
	}

	s, ok := a.(string)
	if !ok {
		return "", false
	}

	return s, true
}

func ParseProtocolFromMap(m map[string]any) (Protocol, error) {
	protoStr, ok := getStr(m, "protocol")
	if !ok {
		return nil, ErrParse
	}

	hashStr, ok := getStr(m, "hash")
	if !ok {
		return nil, ErrParse
	}

	hash := hash.FromString(hashStr)
	if hash == nil {
		return nil, ErrParse
	}

	switch protoStr {
	case "OATH-TOTP":
		tsStr, ok := getStr(m, "timestep")
		if !ok {
			return nil, ErrParse
		}

		ts, err := time.ParseDuration(tsStr)
		if err != nil {
			return nil, ErrParse
		}

		return &OathTotpProtocol{
			Hash:     hash,
			Timestep: ts,
		}, nil

	case "OATH-HOTP":
		return &OathHotpProtocol{
			Hash: hash,
		}, nil

	case "WireGuard":
		return WireGuardProtocol, nil

	case "Noise":
		patternStr, ok := getStr(m, "pattern")
		if !ok {
			return nil, ErrParse
		}

		dhStr, ok := getStr(m, "dh")
		if !ok {
			return nil, ErrParse
		}

		cipherStr, ok := getStr(m, "cipher")
		if !ok {
			return nil, ErrParse
		}

		pattern := pattern.FromString(patternStr)
		if pattern == nil {
			return nil, ErrParse
		}

		dh := dh.FromString(dhStr)
		if dh == nil {
			return nil, ErrParse
		}

		cipher := cipher.FromString(cipherStr)
		if cipher == nil {
			return nil, ErrParse
		}

		return &nyquist.Protocol{
			Pattern: pattern,
			DH:      dh,
			Cipher:  cipher,
			Hash:    hash,
		}, nil
	}

	return nil, ErrParse
}
