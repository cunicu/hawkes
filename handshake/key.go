// SPDX-FileCopyrightText: 2023 Steffen Vogel
// SPDX-License-Identifier: Apache-2.0

package handshake

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"cunicu.li/hawkes/ecdh"
)

var ErrParse = errors.New("failed to parse")

type Key struct {
	Protocol Protocol
	Key      []byte
}

func (k *Key) PrivateKey() (ecdh.PrivateKey, error) {
	return nil, errors.ErrUnsupported
}

func (k *Key) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

func (k *Key) UnmarshalText(t []byte) (err error) {
	s := string(t)

	parts := strings.Split(s, "_")

	var protoParts int

	//nolint:goconst
	switch parts[0] {
	case "Noise", "WireGuard":
		protoParts = 5
	case "OATH-HOTP":
		protoParts = 2
	case "OATH-TOTP":
		protoParts = 3
	}

	if len(parts) != protoParts+1 {
		return ErrParse
	}

	protocol := strings.Join(parts[:protoParts], "_")
	if k.Protocol, err = ParseProtocol(protocol); err != nil {
		return fmt.Errorf("%w: %w", ErrParse, err)
	}

	key := parts[protoParts]
	if k.Key, err = base64.StdEncoding.DecodeString(key); err != nil {
		return fmt.Errorf("%w: %w", ErrParse, err)
	}

	return nil
}

func (k *Key) String() string {
	return fmt.Sprintf("%s_%s", k.Protocol, base64.StdEncoding.EncodeToString(k.Key))
}
