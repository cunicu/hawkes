package pkcs11

// Based on: https://github.com/garnoth/pkclient

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"golang.org/x/term"
)

const (
	CURVE25519_OID_RAW  = "06032B656E"
	NoisePrivateKeySize = 32
	NoisePublicKeySize  = 32
	ERROR_PUBKEY_HSM    = "error getting public key from hsm"
)

type PKClient struct {
	HSM_Session struct {
		slot       uint        // slot to use on the HSM
		key_label  string      // label of derivation key. Unused
		key_id     uint        // ID of the key on the device
		session    p11.Session // session object
		loggedIn   bool        // to track the session login status
		privKeyObj p11.Object  // the private key handle key on the hsm
		pubKeyObj  p11.Object  // the public key handle on the hsm
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
		err := fmt.Errorf("failed to load module library: %s", hsmPath)
		return nil, err
	}
	client.HSM_Session.module = module // save so we can close

	slots, err := module.Slots()
	if err != nil {
		return nil, err
	}
	// try to open a session on the slot
	client.HSM_Session.session, err = slots[slot].OpenWriteSession()
	if err != nil {
		err := fmt.Errorf("failed to open session on slot %d", slot)
		return nil, err
	}
	client.HSM_Session.slot = slot

	// try to login to the slot

	if pin == "ask" {
		retries := 0
		for retries < 2 {
			fmt.Printf("Enter Pin for slot %d:\n", slot)
			userPin, _ := term.ReadPassword(0) // no echo
			pin := strings.TrimSpace(string(userPin))
			err = client.HSM_Session.session.Login(pin)
			if err != nil {
				fmt.Println("Login unsuccessful")
			} else {
				pin = "-1" // don't save the pin
				break
			}
			retries++
		}
	} else {
		err = client.HSM_Session.session.Login(pin)
		if err != nil {
			err = fmt.Errorf("unable to login. error: %w", err)
			return nil, err
		}
	}
	client.HSM_Session.loggedIn = true
	// login successful

	// make sure the hsm has a private curve25519 key for deriving
	client.HSM_Session.privKeyObj, err = client.findDeriveKey(false)
	if err != nil {
		err = fmt.Errorf("failed to find private key for deriving: %w", err)
		return nil, err
	}
	// find the public key of the private key, so we can pass it to the caller later
	client.HSM_Session.pubKeyObj, err = client.findDeriveKey(true)
	if err != nil {
		err = fmt.Errorf("failed to find public key for deriving %w", err)
		return nil, err
	}
	return client, nil
}

// alternate constructor that will not save the hsm pin and prompt
// the user for the pin number
func New_AskPin(hsmPath string, slot uint) (*PKClient, error) {
	client, err := New(hsmPath, slot, "ask")
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Callers should use this when closing to clean-up properly and logout
func (client *PKClient) Close() {
	client.HSM_Session.session.Logout()
	client.HSM_Session.session.Close()
	client.HSM_Session.module.Destroy()
}

// return the public key for the deriving key that was previously found
// this will return whole raw value, it's up the caller to check the length
// this will likely be the full EC_POINT. See PublicKeyNoise()
func (client *PKClient) PublicKeyRaw() ([]byte, error) {
	key, err := client.HSM_Session.pubKeyObj.Value()
	if err != nil {
		return key, err
	}
	return key, nil
}

// Returns a 32 byte length key from the hsm. attempts to convert to a usable WG key
func (client *PKClient) PublicKeyNoise() (key [NoisePublicKeySize]byte, err error) {
	if !client.HSM_Session.loggedIn {
		err := fmt.Errorf("error: must login to hsm first")
		var zkey [NoisePublicKeySize]byte // temp garbage key so we can return the error
		return zkey, err
	}

	srcKey, err := client.HSM_Session.pubKeyObj.Value()

	if err != nil || len(srcKey) < NoisePublicKeySize {
		var zkey [NoisePublicKeySize]byte // temp garbage key so we can return the error
		return zkey, err
	}
	// On a Nitrokey Start, this gets the full EC_POINT value of 34 bytes instead of 32,
	// so if it's > 32 bytes, just return the last 32 bytes.
	if len(srcKey) > NoisePublicKeySize {
		srcKey = srcKey[len(srcKey)-NoisePublicKeySize:]
	}

	copy(key[:], srcKey[:])
	return key, nil
}

// Returns a base64 encoded public key
func (client *PKClient) PublicKeyB64() string {
	srcKey, err := client.PublicKeyNoise()
	if err != nil {
		return ERROR_PUBKEY_HSM
	}
	return base64.StdEncoding.EncodeToString(srcKey[:])
}

// derive a shared secret using the input public key against the private key that was found during setup
// returns a fixed 32 byte array
func (client *PKClient) DeriveNoise(peerPubKey [NoisePublicKeySize]byte) (secret [NoisePrivateKeySize]byte, err error) {
	if !client.HSM_Session.loggedIn {
		err := fmt.Errorf("error: must login to hsm first")
		var zkey [NoisePublicKeySize]byte // temp garbage key so we can return the error
		return zkey, err
	}

	var mech_mech uint = pkcs11.CKM_ECDH1_DERIVE

	// before we call derive, we need to have an array of attributes which specify the type of
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

	// setup the parameters which include the peer's public key
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey[:NoisePublicKeySize])

	var mech *pkcs11.Mechanism = pkcs11.NewMechanism(mech_mech, ecdhParams)

	// derive the secret key from the public key as input and the private key on the device
	tmpKey, err := p11.PrivateKey(client.HSM_Session.privKeyObj).Derive(*mech, attrTemplate)
	if err != nil {
		return secret, err
	}

	copy(secret[:], tmpKey[:NoisePrivateKeySize])
	return secret, err
}

// Try to find a suitable key on the hsm for x25519 key derivation
// parameter GET_PUB_KEY sets the search pattern for a public or private key
func (dev *PKClient) findDeriveKey(GET_PUB_KEY bool) (key p11.Object, err error) {
	//  EC_PARAMS value: the specifc OID for x25519 operation
	rawOID, _ := hex.DecodeString(CURVE25519_OID_RAW)

	keyAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	var keyType *pkcs11.Attribute
	if GET_PUB_KEY {
		keyType = pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY)
	} else {
		keyType = pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)
	}
	keyAttrs = append(keyAttrs, keyType)

	key, err = dev.HSM_Session.session.FindObject(keyAttrs)
	if err != nil {
		return key, err
	}
	return key, nil
}
