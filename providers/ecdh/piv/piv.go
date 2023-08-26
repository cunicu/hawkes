// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"cunicu.li/go-skes/providers/ecdh"
	"github.com/go-piv/piv-go/piv"
	"github.com/katzenpost/nyquist/dh"
)

// piv:yubikey?serial=1234123&pin=1234&slot=

var (
	_ dh.Keypair = (*Keypair)(nil)

	errNotSupported   = errors.New("not supported")
	errSerial         = errors.New("failed to get serial")
	errNoCard         = errors.New("no card found")
	errInvalidSlot    = errors.New("invalid slot")
	errInvalidKeyType = errors.New("invalid key type")
)

type Config struct {
	Card   string
	Serial uint32
	PIN    string
	Slot   uint32
}

type Keypair struct {
	card   string
	serial uint32
	pin    string
	slot   piv.Slot

	publicKey *ecdsa.PublicKey
}

func NewKeypair(cfg Config) (kp *Keypair, err error) {
	slot, ok := slotFromKey(cfg.Slot)
	if !ok {
		return nil, errInvalidSlot
	}

	kp = &Keypair{
		card:   cfg.Card,
		serial: cfg.Serial,
		pin:    cfg.PIN,
		slot:   slot,
	}

	card, err := kp.getCard()
	if err != nil {
		return nil, err
	}
	defer card.Close()

	crt, err := card.Certificate(kp.slot)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if crt.PublicKeyAlgorithm != x509.ECDSA {
		return nil, fmt.Errorf("%w: %s", errInvalidKeyType, crt.PublicKeyAlgorithm)
	}

	kp.publicKey, ok = crt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errInvalidKeyType
	}

	return kp, nil
}

func (kp *Keypair) DH(pk dh.PublicKey) ([]byte, error) {
	card, err := kp.getCard()
	if err != nil {
		return nil, err
	}
	defer card.Close()

	sk, err := card.PrivateKey(kp.slot, kp.publicKey, piv.KeyAuth{
		PIN: kp.pin,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret key: %w", err)
	}

	skECDSA, ok := sk.(*piv.ECDSAPrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: %T", errInvalidKeyType, sk)
	}

	pkECDH, ok := pk.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %T", errInvalidKeyType, pk)
	}

	pkECDSA, err := pkECDH.ECDSA()
	if err != nil {
		return nil, err
	}

	return skECDSA.SharedKey(pkECDSA)
}

// DropPrivate discards the private key.
func (kp *Keypair) DropPrivate() {
	// Do nothing here as we want to keep the key on the token
}

// Public returns the public key of the keypair.
func (kp *Keypair) Public() dh.PublicKey {
	pkECDH, err := kp.publicKey.ECDH()
	if err != nil {
		return nil
	}

	return &ecdh.PublicKey{
		PublicKey: pkECDH,
	}
}

func (kp *Keypair) MarshalBinary() ([]byte, error) {
	return nil, errNotSupported
}

func (kp *Keypair) UnmarshalBinary(_ []byte) error {
	return errNotSupported
}

func (kp *Keypair) getCard() (yk *piv.YubiKey, err error) {
	// Fast-path: we already know a reader name
	if kp.card != "" {
		if yk, err = piv.Open(kp.card); err != nil {
			return nil, err
		} else if kp.serial == 0 {
			return yk, nil
		} else if s, err := yk.Serial(); err != nil {
			return nil, err
		} else if s == kp.serial {
			return yk, nil
		}
	}

	// Slow-path: we dont know a reader name or the serial was wrong
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate cards: %w", err)
	}

	for _, card := range cards {
		if kp.card != "" && !strings.Contains(card, kp.card) {
			continue
		}

		if yk, err = piv.Open(card); err != nil {
			return nil, fmt.Errorf("failed to open card: %w", err)
		}

		if kp.serial != 0 {
			if serial, err := yk.Serial(); err != nil {
				yk.Close()
				return nil, errSerial
			} else if serial != kp.serial {
				yk.Close()
				continue
			}
		}

		// Remember card name for next time
		kp.card = card

		return yk, nil
	}

	return nil, errNoCard
}

func slotFromKey(key uint32) (piv.Slot, bool) {
	switch key {
	case piv.SlotAuthentication.Key:
		return piv.SlotAuthentication, true
	case piv.SlotSignature.Key:
		return piv.SlotSignature, true
	case piv.SlotCardAuthentication.Key:
		return piv.SlotCardAuthentication, true
	case piv.SlotKeyManagement.Key:
		return piv.SlotKeyManagement, true
	}

	return piv.RetiredKeyManagementSlot(key)
}
