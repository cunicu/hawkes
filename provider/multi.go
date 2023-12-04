// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/ebfe/scard"
	"github.com/google/go-tpm/tpm2/transport"
)

var _ Provider = (*MultiProvider)(nil)

// providers is a list of registered providers.
// Feel free to add your own here.
//
//nolint:gochecknoglobals
var (
	providers = map[string]any{}
)

type (
	newProviderStd   func() (Provider, error)
	newProviderSCard func(*scard.Card) (Provider, error)
	NewProviderTPM   func(transport.TPM) (Provider, error)
)

type MultiProviderConfig struct {
	TPMPaths      []string
	FilterReaders func(string) bool
	FilterTPMs    func(string) bool
}

type MultiProvider struct {
	cfg   MultiProviderConfig
	scard *scard.Context

	cards []*scard.Card
	tpms  []transport.TPMCloser

	providers []Provider
}

func NewProvider(cfg MultiProviderConfig) (p *MultiProvider, err error) {
	p = &MultiProvider{
		cfg: cfg,
	}

	if p.scard, err = scard.EstablishContext(); err != nil {
		return nil, fmt.Errorf("failed to establish scard context: %w", err)
	}

	// Enumerate Smartcards and TPMs
	if p.cards, err = p.openCards(); err != nil {
		return nil, fmt.Errorf("failed to get connected smart cards: %w", err)
	}

	if p.tpms, err = p.openTPMs(); err != nil {
		return nil, fmt.Errorf("failed to get trusted platform modules: %w", err)
	}

	for name, ctor := range providers {
		switch ctor := ctor.(type) {
		case newProviderStd:
			provider, err := ctor()
			if err != nil {
				return nil, fmt.Errorf("failed to create %s provider: %w", name, err)
			}

			p.providers = append(p.providers, provider)

		case newProviderSCard:
			for _, card := range p.cards {
				provider, err := ctor(card)
				if err != nil {
					return nil, fmt.Errorf("failed to create %s provider: %w", name, err)
				}

				p.providers = append(p.providers, provider)
			}

		case NewProviderTPM:
			for _, tpm := range p.tpms {
				provider, err := ctor(tpm)
				if err != nil {
					return nil, fmt.Errorf("failed to create %s provider: %w", name, err)
				}

				p.providers = append(p.providers, provider)
			}
		}
	}

	return p, nil
}

func (p *MultiProvider) Close() error {
	for _, card := range p.cards {
		if err := card.Disconnect(scard.LeaveCard); err != nil {
			return err
		}
	}

	for _, tpm := range p.tpms {
		if err := tpm.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (p *MultiProvider) Keys() (allKeys []KeyID, err error) {
	for _, provider := range p.providers {
		keys, err := provider.Keys()
		if err != nil {
			return nil, err
		}

		allKeys = append(allKeys, keys...)
	}

	return allKeys, nil
}

func (p *MultiProvider) CreateKey(_ /*label*/ string) (KeyID, error) {
	return nil, errors.ErrUnsupported
}

func (p *MultiProvider) DestroyKey(KeyID) error {
	return errors.ErrUnsupported
}

func (p *MultiProvider) OpenKey(KeyID) (PrivateKey, error) {
	return nil, errors.ErrUnsupported
}

func (p *MultiProvider) openCards() (cards []*scard.Card, err error) {
	readers, err := p.scard.ListReaders()
	if err != nil {
		return nil, fmt.Errorf("failed to list readers: %w", err)
	}

	for _, reader := range readers {
		if !p.cfg.FilterReaders(reader) {
			continue
		}

		card, err := p.scard.Connect(reader, scard.ShareShared, scard.ProtocolAny)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to reader: %w", err)
		}

		cards = append(cards, card)
	}

	return cards, nil
}

func (p *MultiProvider) openTPMs() (tpms []transport.TPMCloser, err error) {
	tpmDevPaths := p.cfg.TPMPaths

	if tpmDevPaths == nil {
		tpmDevPaths = p.findTPMs()
	}

	if len(tpmDevPaths) == 0 {
		// Find Windows TPM
		tpm, err := transport.OpenTPM()
		if err != nil {
			return nil, err
		}

		tpms = append(tpms, tpm)
	} else {
		for _, tpmDevPath := range tpmDevPaths {
			if !p.cfg.FilterTPMs(tpmDevPath) {
				continue
			}

			tpm, err := transport.OpenTPM(tpmDevPath)
			if err != nil {
				return nil, err
			}

			tpms = append(tpms, tpm)
		}
	}

	return tpms, nil
}

func (p *MultiProvider) findTPMs() (tpmDevPaths []string) {
	for i := 0; ; i++ {
		tpmrmDevPath := fmt.Sprintf("/dev/tpmrm%d", i)
		if fi, err := os.Stat(tpmrmDevPath); err == nil && fi.Mode().Type() == fs.ModeCharDevice {
			tpmDevPaths = append(tpmDevPaths, tpmrmDevPath)
			continue
		}

		tpmDevPath := fmt.Sprintf("/dev/tpm%d", i)
		if fi, err := os.Stat(tpmDevPath); err == nil && fi.Mode().Type() == fs.ModeCharDevice {
			tpmDevPaths = append(tpmDevPaths, tpmDevPath)
			continue
		}

		break
	}

	return tpmDevPaths
}

func Register(name string, p any) {
	providers[name] = p
}
