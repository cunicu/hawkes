// SPDX-FileCopyrightText: 2023 age-plugin-tpm Authors
// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: MIT

package tpm2

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/katzenpost/nyquist/dh"

	ecdhx "cunicu.li/go-skes/providers/ecdh"
)

// See:
// - https://linderud.dev/blog/golang-crypto/ecdh-and-the-tpm/
// - https://ericchiang.github.io/post/tpm-keys/
// - https://github.com/Foxboron/age-plugin-tpm
// - https://www.youtube.com/watch?v=S6HWK8PF5MU

type Config struct {
	TPM      transport.TPMCloser
	PinEntry func() ([]byte, error)
}

var _ (dh.Keypair) = (*Keypair)(nil)

type Keypair struct {
	tpm      transport.TPMCloser
	pinEntry func() ([]byte, error)

	private tpm2.TPM2BPrivate
	public  tpm2.TPM2BPublic
}

func GenerateKeypair(cfg Config) (*Keypair, error) {
	srkHandle, srkPublic, err := createSRK(cfg.TPM)
	if err != nil {
		return nil, fmt.Errorf("failed to create SRK: %w", err)
	}

	defer flushHandle(cfg.TPM, srkHandle)

	eccKey := tpm2.Create{
		ParentHandle: srkHandle,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDH,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDH,
							&tpm2.TPMSKeySchemeECDH{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
		}),
	}

	if cfg.PinEntry != nil {
		pin, err := cfg.PinEntry()
		if err != nil {
			return nil, fmt.Errorf("failed to get pin")
		}

		eccKey.InSensitive = tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: pin,
				},
			},
		}
	}

	eccRsp, err := eccKey.Execute(cfg.TPM,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM key: %w", err)
	}

	return &Keypair{
		tpm:      cfg.TPM,
		pinEntry: cfg.PinEntry,
		private:  eccRsp.OutPrivate,
		public:   eccRsp.OutPublic,
	}, nil
}

func LoadKeypair(cfg Config, b []byte) (*Keypair, error) {
	kp := &Keypair{
		tpm:      cfg.TPM,
		pinEntry: cfg.PinEntry,
	}

	if err := kp.UnmarshalBinary(b); err != nil {
		return nil, err
	}

	srkHandle, _, err := createSRK(cfg.TPM)
	if err != nil {
		return nil, err
	}

	defer flushHandle(cfg.TPM, srkHandle)

	if _, err := loadKeypairWithParent(cfg.TPM, *srkHandle, kp); err != nil {
		return nil, err
	}

	return kp, err
}

func (kp *Keypair) DH(pk dh.PublicKey) ([]byte, error) {
	ecpk, ok := pk.(*ecdhx.PublicKey)
	if !ok {
		return nil, ecdhx.ErrInvalidPublicKey
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), ecpk.Bytes())
	if x == nil {
		return nil, ecdhx.ErrInvalidPublicKey
	}

	// We'll be using the SRK for the session encryption, and we need it as the
	// parent for our application key. Make sure it's created and available.
	srkHandle, srkPublic, err := createSRK(kp.tpm)
	if err != nil {
		return nil, err
	}
	defer flushHandle(kp.tpm, srkHandle)

	// We load the key pair into the TPM, using the SRK parent.
	handle, err := loadKeypairWithParent(kp.tpm, *srkHandle, kp)
	if err != nil {
		return nil, err
	}
	defer flushHandle(kp.tpm, handle.Handle)

	// Add the AuthSession for the handle
	if kp.pinEntry != nil {
		pin, err := kp.pinEntry()
		if err != nil {
			return nil, fmt.Errorf("failed to get pin: %w", err)
		}

		handle.Auth = tpm2.PasswordAuth(pin)
	}

	// ECDHZGen command for the TPM, turns the sesion key into something we understand.
	ecdh := tpm2.ECDHZGen{
		KeyHandle: *handle,
		InPoint: tpm2.New2B(
			tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: x.FillBytes(make([]byte, 32)),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: y.FillBytes(make([]byte, 32)),
				},
			},
		),
	}

	// Execute the ECDHZGen command, we also add session encryption.
	// In this case the session encryption only encrypts the private part going out of the TPM, which is the shared
	// session key we are using in our kdf.
	ecdhRsp, err := ecdh.Execute(kp.tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptOut),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed ecdhzgen: %w", err)
	}

	shared, err := ecdhRsp.OutPoint.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed getting ecdh point: %w", err)
	}

	return shared.X.Buffer, nil
}

// DropPrivate discards the private key.
func (kp *Keypair) DropPrivate() {
	// Do nothing here as we want to keep the key on the token
}

// Public returns the public key of the keypair.
func (kp *Keypair) Public() dh.PublicKey {
	pub, err := kp.public.Contents()
	if err != nil {
		return nil
	}

	ecc, err := pub.Unique.ECC()
	if err != nil {
		return nil
	}

	ecdhKey, err := ecdh.P256().NewPublicKey(elliptic.Marshal(elliptic.P256(),
		big.NewInt(0).SetBytes(ecc.X.Buffer),
		big.NewInt(0).SetBytes(ecc.Y.Buffer),
	))

	return &ecdhx.PublicKey{
		PublicKey: ecdhKey,
	}
}

func (kp *Keypair) MarshalBinary() (out []byte, err error) {
	out = append(out, tpm2.Marshal(kp.public)...)
	out = append(out, tpm2.Marshal(kp.private)...)

	return out, nil
}

func (kp *Keypair) UnmarshalBinary(b []byte) error {
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b)
	if err != nil {
		return err
	}

	b = b[len(public.Bytes())+2:]

	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b)
	if err != nil {
		return err
	}

	kp.public = *public
	kp.private = *private

	return nil
}

// Creates a Storage Key, or return the loaded storage key
func createSRK(tpm transport.TPMCloser) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err := srk.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating primary key: %w", err)
	}

	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting srk public content: %w", err)
	}

	return &tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, nil
}

func loadKeypairWithParent(tpm transport.TPMCloser, parent tpm2.AuthHandle, kp *Keypair) (*tpm2.AuthHandle, error) {
	loadBlobCmd := tpm2.Load{
		ParentHandle: parent,
		InPrivate:    kp.private,
		InPublic:     kp.public,
	}

	loadBlobRsp, err := loadBlobCmd.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed getting handle: %w", err)
	}

	// Return a AuthHandle with a nil PasswordAuth
	return &tpm2.AuthHandle{
		Handle: loadBlobRsp.ObjectHandle,
		Name:   loadBlobRsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, nil
}

// shadow the unexported interface from go-tpm
type handle interface {
	HandleValue() uint32
	KnownName() *tpm2.TPM2BName
}

// Helper to flush handles
func flushHandle(tpm transport.TPM, h handle) {
	flush := tpm2.FlushContext{FlushHandle: h}
	flush.Execute(tpm) //nolint:errcheck
}
