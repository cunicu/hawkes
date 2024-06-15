// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bytes"
	"errors"
	"os"

	se "cunicu.li/hawkes/ecdh/applese"
)

var ErrKeyNotFound = errors.New("key not found")

var _ PrivateKeyDH = (*appleSecureEnclaveKey)(nil)

type appleSecureEnclaveKey struct {
	se.PrivateKey
}

func (k *appleSecureEnclaveKey) ID() KeyID {
	return keyID(k.Public())
}

func (k *appleSecureEnclaveKey) Details() map[string]any {
	return map[string]any{} // TODO
}

func (k *appleSecureEnclaveKey) Close() error {
	// TODO: Release SecKeyRef?
	return nil
}

var _ Provider = (*appleSecureEnclaveProvider)(nil)

type appleSecureEnclaveProvider struct{}

func newAppleSecureEnclaveProvider() (Provider, error) {
	return &appleSecureEnclaveProvider{}, nil
}

func (p *appleSecureEnclaveProvider) Keys() (keyIDs []KeyID, err error) {
	keys, err := se.Keys(nil)
	if err != nil {
		return nil, err
	}

	for _, sk := range keys {
		keyIDs = append(keyIDs, keyID(sk.Public()))
	}

	return keyIDs, nil
}

func (p *appleSecureEnclaveProvider) CreateKey(label string) (KeyID, error) {
	sk, err := se.GenerateKey(label)
	if err != nil {
		return nil, err
	}

	return keyID(sk.Public()), nil
}

func (p *appleSecureEnclaveProvider) OpenKey(id KeyID) (PrivateKey, error) {
	label, err := p.keyLabel(id)
	if err != nil {
		return nil, err
	}

	sk, err := se.PrivateKeyByLabel(label)
	if err != nil {
		return nil, err
	}

	return &appleSecureEnclaveKey{
		PrivateKey: sk,
	}, nil
}

func (p *appleSecureEnclaveProvider) DestroyKey(id KeyID) error {
	label, err := p.keyLabel(id)
	if err != nil {
		return err
	}

	ok, err := se.RemoveKey(label)
	if err != nil {
		return err
	}

	if !ok {
		return ErrKeyNotFound
	}

	return nil
}

func (p *appleSecureEnclaveProvider) keyLabel(id KeyID) (se.KeyLabel, error) {
	keys, err := se.Keys(nil)
	if err != nil {
		return se.KeyLabel{}, err
	}

	for _, key := range keys {
		keyID := keyID(key.Public())
		if bytes.Equal(id, keyID) {
			return key.Label(), nil
		}
	}

	return se.KeyLabel{}, os.ErrNotExist
}

//nolint:gochecknoinits
func init() {
	Register("AppleSE", newAppleSecureEnclaveProvider)
}
