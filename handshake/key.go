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

func (id *Key) PrivateKey() (ecdh.PrivateKey, error) {
	return nil, errors.ErrUnsupported
}

func (i *Key) MarshalText() ([]byte, error) {
	return []byte(i.String()), nil
}

func (i *Key) UnmarshalText(t []byte) (err error) {
	s := string(t)

	parts := strings.Split(s, "_")

	var protoParts int
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
	if i.Protocol, err = ParseProtocol(protocol); err != nil {
		return fmt.Errorf("%w: %w", ErrParse, err)
	}

	key := parts[protoParts]
	if i.Key, err = base64.StdEncoding.DecodeString(key); err != nil {
		return fmt.Errorf("%w: %w", ErrParse, err)
	}

	return nil
}

func (i *Key) String() string {
	return fmt.Sprintf("%s_%s", i.Protocol, base64.StdEncoding.EncodeToString(i.Key))
}
