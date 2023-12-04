// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/katzenpost/nyquist/dh"

	"cunicu.li/hawkes/ecdh/sw"
)

var (
	_ PrivateKeyHMAC = (*fileKey)(nil)
	_ PrivateKeyDH   = (*fileKey)(nil)

	//nolint:gochecknoglobals
	cfg = sw.Config{
		Curve:  ecdh.P256(),
		Random: rand.Reader,
	}
)

type fileKey struct {
	key   []byte
	label string
}

func (k *fileKey) ID() KeyID {
	sk, err := sw.LoadPrivateKey(cfg, k.key)
	if err != nil {
		panic(err) // TODO
	}

	return keyID(sk.Public())
}

func (k *fileKey) Details() map[string]any {
	return map[string]any{
		"label": k.label,
	}
}

func (k *fileKey) HMAC(chal []byte) ([]byte, error) {
	h := hmac.New(sha256.New, k.key)
	h.Write(chal)
	return h.Sum(nil), nil
}

func (k *fileKey) DH(pk dh.PublicKey) ([]byte, error) {
	sk, err := sw.LoadPrivateKey(cfg, k.key)
	if err != nil {
		return nil, err
	}

	return sk.DH(pk)
}

func (k *fileKey) Public() dh.PublicKey {
	sk, err := sw.LoadPrivateKey(cfg, k.key)
	if err != nil {
		return nil
	}

	return sk.Public()
}

func (k *fileKey) Close() error {
	return nil
}

var _ Provider = (*fileProvider)(nil)

type fileProvider struct {
	keyDir string
}

func newFileProvider() (Provider, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to find user home directory: %w", err)
	}
	keyDir := filepath.Join(homeDir, ".hawkes")

	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create: %s: %w", keyDir, err)
	}

	return &fileProvider{
		keyDir: keyDir,
	}, nil
}

func (p *fileProvider) Keys() (keyIDs []KeyID, err error) {
	keys, err := p.keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		sk, err := sw.LoadPrivateKey(cfg, key)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}

		keyIDs = append(keyIDs, keyID(sk.Public()))
	}

	return keyIDs, nil
}

func (p *fileProvider) OpenKey(id KeyID) (PrivateKey, error) {
	label, key, err := p.keyByID(id)
	if err != nil {
		return nil, err
	}

	return &fileKey{
		key:   key,
		label: label,
	}, nil
}

func (p *fileProvider) CreateKeyFromSecret(label string, secret []byte) (KeyID, error) {
	keyFile := filepath.Join(p.keyDir, label+".key")

	// Check that file does not exist yet
	if _, err := os.Stat(keyFile); err == nil {
		return nil, os.ErrExist
	}

	sk, err := sw.LoadPrivateKey(cfg, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	return keyID(sk.Public()), os.WriteFile(keyFile, sk.Bytes(), 0o600)
}

func (p *fileProvider) CreateKey(label string) (KeyID, error) {
	keyFile := filepath.Join(p.keyDir, label+".key")

	// Check that file does not exist yet
	if _, err := os.Stat(keyFile); err == nil {
		return nil, os.ErrExist
	}

	sk, err := sw.GeneratePrivateKey(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return keyID(sk.Public()), os.WriteFile(keyFile, sk.Bytes(), 0o600)
}

func (p *fileProvider) DestroyKey(id KeyID) error {
	keyFile, err := p.keyFileByID(id)
	if err != nil {
		return err
	}

	return os.Remove(keyFile)
}

func (p *fileProvider) keys() (map[string][]byte, error) {
	keyFiles, err := p.keyFiles()
	if err != nil {
		return nil, err
	}

	keys := map[string][]byte{}

	for _, keyFile := range keyFiles {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		keys[keyFile] = key
	}

	return keys, nil
}

func (p *fileProvider) keyFiles() ([]string, error) {
	des, err := os.ReadDir(p.keyDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to list directory contents: %w", err)
	}

	keyFiles := []string{}

	for _, de := range des {
		if de.IsDir() {
			continue
		}

		if filepath.Ext(de.Name()) != ".key" {
			continue
		}

		keyFile := filepath.Join(p.keyDir, de.Name())
		keyFiles = append(keyFiles, keyFile)
	}

	return keyFiles, nil
}

func (p *fileProvider) keyFileByID(id KeyID) (string, error) {
	keys, err := p.keys()
	if err != nil {
		return "", err
	}

	for keyLabel, key := range keys {
		sk, err := ecdh.P256().NewPrivateKey(key)
		if err != nil {
			return "", fmt.Errorf("failed to load private key: %w", err)
		}

		pk := sk.Public().(*ecdh.PublicKey) //nolint:forcetypeassert

		digest := sha256.New()
		digest.Write(pk.Bytes())
		keyID := KeyID(digest.Sum(nil))

		if bytes.Equal(keyID, id) {
			return keyLabel, nil
		}
	}

	return "", os.ErrNotExist
}

func (p *fileProvider) keyByID(id KeyID) (string, []byte, error) {
	keyFile, err := p.keyFileByID(id)
	if err != nil {
		return "", nil, err
	}

	keyLabel := filepath.Base(keyFile)
	keyLabel = strings.TrimSuffix(keyLabel, ".key")
	key, err := os.ReadFile(keyFile)

	return keyLabel, key, err
}

//nolint:gochecknoinits
func init() {
	Register("File", newFileProvider)
}
