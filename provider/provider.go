// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

// Package provider implements a common interface for token and smartcards which provide secret key material.
package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"cunicu.li/hawkes/ecdh"
	"github.com/katzenpost/nyquist/dh"
)

var (
	ErrSlotType                 = errors.New("invalid slot type")
	ErrParse                    = errors.New("failed to parse")
	ErrUnsupportedCurve         = errors.New("unsupported curve")
	ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")
	ErrUnsupportedProtocol      = errors.New("unsupported protocol")
)

type KeyID []byte

func (i KeyID) String() string {
	return base64.StdEncoding.EncodeToString(i)
}

func keyID(sk dh.PublicKey) KeyID {
	digest := sha256.New()
	digest.Write(sk.Bytes())
	return KeyID(digest.Sum(nil))
}

type Provider interface {
	// Keys enumerates all keys available via this provider.
	Keys() ([]KeyID, error)

	// CreateKey creates a new key with the given human-readable label.
	CreateKey(label string) (KeyID, error)

	// OpenKey opens a key for cryptographic operations.
	OpenKey(KeyID) (PrivateKey, error)

	// DestroyKey removes the cryptographic key material from the provider.
	DestroyKey(KeyID) error
}

type PrivateKey interface {
	// ID returns the keys unique identifier.
	// For elliptic curve keys its the SHA256 digest of the public key.
	// For HMAC keys its the output of HMAC([]).
	ID() KeyID

	// Details returns a dictionary of the keys auxiliary attributes.
	Details() map[string]any

	// Close closes any internal handles to the key.
	Close() error
}

type PrivateKeyDH interface {
	PrivateKey

	ecdh.PrivateKey
}

type PrivateKeyHMAC interface {
	PrivateKey

	HMAC(challenge []byte) ([]byte, error)
}
