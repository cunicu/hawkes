// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/go-piv/piv-go/piv"
)

var errWrongKeyType = errors.New("wrong key type")

func main() {
	if len(os.Args) < 2 {
		return
	}

	// List all smartcards connected to the system.
	cards, err := piv.Cards()
	if err != nil {
		panic(err)
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				panic(err)
			}
			break
		}
	}
	if yk == nil {
		panic("no yubikey found")
	}

	defer yk.Close()

	switch os.Args[1] {
	case "cert":
		err = cert(yk)
	case "decrypt":
		err = decrypt(yk)
	case "encrypt":
		err = encrypt(yk)
	}

	if err != nil {
		log.Print(err)
	}
}

func cert(yk *piv.YubiKey) error {
	// sn, _ := yk.Serial()
	// fmt.Printf("Version: %d.%d.%d\n", yk.Version().Major, yk.Version().Minor, yk.Version().Patch)
	// fmt.Printf("Serial: %d\n", sn)

	crt, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %w", err)
	}

	// Print the certificate
	// result, err := certinfo.CertificateText(crt)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Print(result)

	pemPayload, _ := x509.MarshalPKIXPublicKey(crt.PublicKey.(*rsa.PublicKey))

	if err := pem.Encode(os.Stdout, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pemPayload,
	}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	return nil
}

func encrypt(yk *piv.YubiKey) error {
	pt, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	crt, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return fmt.Errorf("failed to get certficate: %w", err)
	}

	pk, ok := crt.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errWrongKeyType
	}

	ct, err := rsa.EncryptPKCS1v15(rand.Reader, pk, pt)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	if _, err := os.Stdout.Write(ct); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}

	return nil
}

func decrypt(yk *piv.YubiKey) error {
	ct, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read from stdin: %w", err)
	}

	crt, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return fmt.Errorf("failed to get certficate: %w", err)
	}

	sk, err := yk.PrivateKey(piv.SlotSignature, crt.PublicKey, piv.KeyAuth{
		PIN: "111111",
	})
	if err != nil {
		return fmt.Errorf("failed to get secret key: %w", err)
	}

	dec, ok := sk.(crypto.Decrypter)
	if !ok {
		return errWrongKeyType
	}

	pt, err := dec.Decrypt(rand.Reader, ct, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	if _, err := os.Stdout.Write(pt); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}

	return nil
}
