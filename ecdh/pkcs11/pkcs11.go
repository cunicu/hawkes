// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

// Package pkcs11 provides an ECDH implementation backed by an PKCS11 compatible token or HSM.
package pkcs11

// Based on: https://github.com/garnoth/pkclient

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

const (
	Curve25519OidRaw    = "06032B656E"
	NoisePrivateKeySize = 32
	NoisePublicKeySize  = 32
)

var (
	errFailedToLoadLibrary = errors.New("failed to load module library")
	errLogin               = errors.New("error: must login to hsm first")
	errSession             = errors.New("failed to open session")
)

type PKClient struct {
	HSMSession struct {
		slot       uint        // Slot to use on the HSM
		keyLabel   string      // Label of derivation key. Unused
		keyID      uint        // ID of the key on the device
		session    p11.Session // Session object
		loggedIn   bool        // To track the session login status
		privKeyObj p11.Object  // The private key handle key on the hsm
		pubKeyObj  p11.Object  // The public key handle on the hsm
		module     p11.Module
	}
}

// Try to open a session with the HSM, select the slot and login to it
// A public and private key must already exist on the hsm
// The private and match public key must also be found during setup
// The private key must be the Curve25519 Algorithm, OID 1.3.101.110
func New(hsmPath string, slot uint, pin string) (*PKClient, error) {
	client := new(PKClient)
	module, err := p11.OpenModule(hsmPath)
	if err != nil {
		err := fmt.Errorf("%w: %s", errFailedToLoadLibrary, hsmPath)
		return nil, err
	}
	client.HSMSession.module = module // Save so we can close

	slots, err := module.Slots()
	if err != nil {
		return nil, err
	}

	// Try to open a session on the slot
	client.HSMSession.session, err = slots[slot].OpenWriteSession()
	if err != nil {
		err := fmt.Errorf("%w on slot %d", errSession, slot)
		return nil, err
	}
	client.HSMSession.slot = slot

	// Try to login to the slot
	err = client.HSMSession.session.Login(pin)
	if err != nil {
		err = fmt.Errorf("unable to login. error: %w", err)
		return nil, err
	}

	client.HSMSession.loggedIn = true
	// Login successful

	// Make sure the hsm has a private curve25519 key for deriving
	client.HSMSession.privKeyObj, err = client.findDeriveKey(false)
	if err != nil {
		err = fmt.Errorf("failed to find private key for deriving: %w", err)
		return nil, err
	}

	// Find the public key of the private key, so we can pass it to the caller later
	client.HSMSession.pubKeyObj, err = client.findDeriveKey(true)
	if err != nil {
		err = fmt.Errorf("failed to find public key for deriving %w", err)
		return nil, err
	}
	return client, nil
}

// Alternate constructor that will not save the hsm pin and prompt the user for the pin number
func NewAskPin(hsmPath string, slot uint) (*PKClient, error) {
	client, err := New(hsmPath, slot, "ask")
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Callers should use this when closing to clean-up properly and logout
func (c *PKClient) Close() error {
	if err := c.HSMSession.session.Logout(); err != nil {
		return err
	}

	c.HSMSession.session.Close()
	c.HSMSession.module.Destroy()

	return nil
}

// Return the public key for the deriving key that was previously found.
// This will return whole raw value, it's up the caller to check the length.
// This will likely be the full EC_POINT. See PublicKeyNoise().
func (c *PKClient) PublicKeyRaw() ([]byte, error) {
	key, err := c.HSMSession.pubKeyObj.Value()
	if err != nil {
		return key, err
	}
	return key, nil
}

// Returns a 32 byte length key from the hsm. attempts to convert to a usable WG key
func (c *PKClient) PublicKeyNoise() (key [NoisePublicKeySize]byte, err error) {
	if !c.HSMSession.loggedIn {
		return key, errLogin
	}

	srcKey, err := c.HSMSession.pubKeyObj.Value()

	if err != nil || len(srcKey) < NoisePublicKeySize {
		return key, err
	}

	// On a NitroKey Start, this gets the full EC_POINT value of 34 bytes instead of 32,
	// so if it's > 32 bytes, just return the last 32 bytes.
	if len(srcKey) > NoisePublicKeySize {
		srcKey = srcKey[len(srcKey)-NoisePublicKeySize:]
	}

	copy(key[:], srcKey)
	return key, nil
}

// Derive a shared secret using the input public key against the private key that was found during setup.
// Returns a fixed 32 byte array.
func (c *PKClient) DeriveNoise(peerPubKey [NoisePublicKeySize]byte) (secret [NoisePrivateKeySize]byte, err error) {
	if !c.HSMSession.loggedIn {
		return secret, errLogin
	}

	var mechMech uint = pkcs11.CKM_ECDH1_DERIVE

	// Before we call derive, we need to have an array of attributes which specify the type of
	// key to be returned, in our case, it's the shared secret key, produced via deriving
	// This template pulled from OpenSC pkcs11-tool.c line 4038
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	// Setup the parameters which include the peer's public key
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey[:NoisePublicKeySize])

	mech := pkcs11.NewMechanism(mechMech, ecdhParams)

	// Derive the secret key from the public key as input and the private key on the device
	sk := p11.PrivateKey(c.HSMSession.privKeyObj)
	tmpKey, err := sk.Derive(*mech, attrTemplate)
	if err != nil {
		return secret, err
	}

	copy(secret[:], tmpKey[:NoisePrivateKeySize])
	return secret, err
}

// Try to find a suitable key on the hsm for x25519 key derivation
// parameter GET_PUB_KEY sets the search pattern for a public or private key
func (c *PKClient) findDeriveKey(getPubKey bool) (key p11.Object, err error) {
	//  EC_PARAMS value: the specific OID for x25519 operation
	rawOID, _ := hex.DecodeString(Curve25519OidRaw)

	keyAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	var keyType *pkcs11.Attribute
	if getPubKey {
		keyType = pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY)
	} else {
		keyType = pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)
	}
	keyAttrs = append(keyAttrs, keyType)

	key, err = c.HSMSession.session.FindObject(keyAttrs)
	if err != nil {
		return key, err
	}

	return key, nil
}
