// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-FileCopyrightText: 2023 Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

// Package sw provides an ECDH implementation backed by an Apple Secure Enclave.
//
//nolint:gci
package applese

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"unsafe"

	"github.com/katzenpost/nyquist/dh"

	ecdhx "cunicu.li/hawkes/ecdh"
	"cunicu.li/hawkes/ecdh/sw"
)

/*
#cgo LDFLAGS: -framework Security

#include <Security/Security.h>
*/
import "C"

var (
	errExtractingPublicKey  = errors.New("failed to extract public key")
	errInvalidPublicKeyType = errors.New("invalid public key type")
	errGeneratingPrivateKey = errors.New("failed to generate secret key")
)

const (
	nilSecKey           C.SecKeyRef           = 0
	nilSecAccessControl C.SecAccessControlRef = 0

	tag = "li.cunicu.hawkes.se.v1"
)

type KeyLabel [sha1.Size]byte

func (l KeyLabel) String() string {
	return base64.StdEncoding.EncodeToString(l[:])
}

var _ ecdhx.PrivateKey = (PrivateKey)(0)

type PrivateKey C.SecKeyRef

func (k PrivateKey) Label() KeyLabel {
	keyAttrs := C.SecKeyCopyAttributes(C.SecKeyRef(k))
	defer C.CFRelease(C.CFTypeRef(keyAttrs))

	appLabelRef := C.CFDataRef(C.CFDictionaryGetValue(keyAttrs, unsafe.Pointer(C.kSecAttrApplicationLabel)))

	appLabelBytes := cfDataToBytes(appLabelRef)

	return KeyLabel(appLabelBytes)
}

func (k PrivateKey) Public() dh.PublicKey {
	pkRef := C.SecKeyCopyPublicKey(C.SecKeyRef(k))
	defer C.CFRelease(C.CFTypeRef(pkRef))

	keyAttrs := C.SecKeyCopyAttributes(pkRef)
	defer C.CFRelease(C.CFTypeRef(keyAttrs))

	val := C.CFDataRef(C.CFDictionaryGetValue(keyAttrs, unsafe.Pointer(C.kSecValueData)))
	if val == nilCFData {
		panic(errExtractingPublicKey) // TODO
	}

	pkBytes := C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(val)),
		C.int(C.CFDataGetLength(val)),
	)

	pk, _ := sw.P256.ParsePublicKey(pkBytes) // TODO

	return pk
}

func (k PrivateKey) DH(pk dh.PublicKey) ([]byte, error) {
	params, err := newCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecKeyKeyExchangeParameterRequestedSize): C.CFTypeRef(newCFNumber(32)),
	})
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(params))

	pkRef, err := loadPublicKey(pk)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(pkRef))

	var eRef C.CFErrorRef
	ssRef := C.SecKeyCopyKeyExchangeResult(C.SecKeyRef(k), C.kSecKeyAlgorithmECDHKeyExchangeStandard, pkRef, params, &eRef) //nolint:gocritic
	if err := goError(eRef); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(ssRef))

	return cfDataToBytes(ssRef), nil
}

// GenerateKey creates a key with the given label and tag.
// Returns public key raw data.
func GenerateKey(label string) (PrivateKey, error) {
	protection := C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
	flags := C.kSecAccessControlPrivateKeyUsage

	var eRef C.CFErrorRef
	access := C.SecAccessControlCreateWithFlags(
		C.kCFAllocatorDefault,
		C.CFTypeRef(protection),
		C.SecAccessControlCreateFlags(flags),
		&eRef) //nolint:gocritic
	if err := goError(eRef); err != nil {
		C.CFRelease(C.CFTypeRef(eRef))
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(access))

	cfTag, err := newCFData([]byte(tag))
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	cfLabel, err := newCFData([]byte(label))
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(cfLabel))

	skAttrs, err := newCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrAccessControl):  C.CFTypeRef(access),
		C.CFTypeRef(C.kSecAttrIsPermanent):    C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecAttrApplicationTag): C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrLabel):          C.CFTypeRef(cfLabel),
	})
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(skAttrs))

	attrs, err := newCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrKeyType):       C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom),
		C.CFTypeRef(C.kSecAttrKeySizeInBits): C.CFTypeRef(newCFNumber(256)),
		C.CFTypeRef(C.kSecAttrTokenID):       C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave),
		C.CFTypeRef(C.kSecPrivateKeyAttrs):   C.CFTypeRef(skAttrs),
	})
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	skRef := C.SecKeyCreateRandomKey(attrs, &eRef) //nolint:gocritic
	if err := goError(eRef); err != nil {
		C.CFRelease(C.CFTypeRef(eRef))
		return 0, err
	} else if skRef == nilSecKey {
		return 0, errGeneratingPrivateKey
	}

	return PrivateKey(skRef), nil
}

// RemoveKey tries to delete a key identified by label, tag and hash.
// hash is the SHA1 of the key. Can be nil
// If hash is nil then all the keys that match the label and tag specified will
// be deleted.
// Returns true if the key was found and deleted successfully
func RemoveKey(key KeyLabel) (bool, error) {
	cfTag, err := newCFData([]byte(tag))
	if err != nil {
		return false, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	cfAppLabel, err := newCFData(key[:])
	if err != nil {
		return false, err
	}
	defer C.CFRelease(C.CFTypeRef(cfAppLabel))

	m := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):        C.CFTypeRef(C.kSecClassKey),
		C.CFTypeRef(C.kSecAttrKeyClass): C.CFTypeRef(C.kSecAttrKeyClassPrivate),
		C.CFTypeRef(C.kSecAttrKeyType):  C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom),
		C.CFTypeRef(C.kSecAttrTokenID):  C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave),
		// C.CFTypeRef(C.kSecAttrApplicationTag):   C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrApplicationLabel): C.CFTypeRef(cfAppLabel),
	}

	query, err := newCFDictionary(m)
	if err != nil {
		return false, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var st C.OSStatus = C.errSecDuplicateItem
	for st == C.errSecDuplicateItem {
		st = C.SecItemDelete(query)
	}
	if err := goError(st); err != nil {
		return false, err
	}
	return true, nil
}

func Keys(hash []byte) ([]PrivateKey, error) {
	m := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):        C.CFTypeRef(C.kSecClassKey),
		C.CFTypeRef(C.kSecAttrKeyClass): C.CFTypeRef(C.kSecAttrKeyClassPrivate),
		C.CFTypeRef(C.kSecAttrKeyType):  C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom),
		C.CFTypeRef(C.kSecAttrTokenID):  C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave),
		C.CFTypeRef(C.kSecReturnRef):    C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit):   C.CFTypeRef(C.kSecMatchLimitAll),
	}

	if hash != nil {
		cfAppLabel, err := newCFData(hash)
		if err != nil {
			return nil, err
		}
		defer C.CFRelease(C.CFTypeRef(cfAppLabel))

		m[C.CFTypeRef(C.kSecAttrApplicationLabel)] = C.CFTypeRef(cfAppLabel)
	}

	query, err := newCFDictionary(m)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result) //nolint:gocritic
	if err := goError(status); err != nil {
		if errors.Is(err, errKeyNotFound) {
			return nil, nil
		}

		return nil, err
	}
	defer C.CFRelease(result)

	// Don't need to release queryResult since the abstract result is released above.
	queryResult := C.CFArrayRef(result)

	n := C.CFArrayGetCount(queryResult)
	refs := make([]PrivateKey, n)
	C.CFArrayGetValues(queryResult, C.CFRange{0, n}, (*unsafe.Pointer)(unsafe.Pointer(&refs[0])))

	for _, ref := range refs {
		C.CFRetain(C.CFTypeRef(ref))
	}

	return refs, nil
}

func PrivateKeyByLabel(label KeyLabel) (PrivateKey, error) {
	cfTag, err := newCFData([]byte(tag))
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	cfAppLabel, err := newCFData(label[:])
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(cfAppLabel))

	m := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):                C.CFTypeRef(C.kSecClassKey),
		C.CFTypeRef(C.kSecAttrKeyClass):         C.CFTypeRef(C.kSecAttrKeyClassPrivate),
		C.CFTypeRef(C.kSecAttrKeyType):          C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom),
		C.CFTypeRef(C.kSecAttrTokenID):          C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave),
		C.CFTypeRef(C.kSecAttrApplicationTag):   C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrApplicationLabel): C.CFTypeRef(cfAppLabel),
		C.CFTypeRef(C.kSecReturnRef):            C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit):           C.CFTypeRef(C.kSecMatchLimitOne),
	}

	query, err := newCFDictionary(m)
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var keyRef C.CFTypeRef
	status := C.SecItemCopyMatching(query, &keyRef) //nolint:gocritic
	if err := goError(status); err != nil {
		return 0, err
	}

	return PrivateKey(keyRef), nil
}

func loadPublicKey(pk dh.PublicKey) (C.SecKeyRef, error) {
	attrs, err := newCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrKeyClass):      C.CFTypeRef(C.kSecAttrKeyClassPublic),
		C.CFTypeRef(C.kSecAttrKeyType):       C.CFTypeRef(C.kSecAttrKeyTypeECSECPrimeRandom),
		C.CFTypeRef(C.kSecAttrKeySizeInBits): C.CFTypeRef(newCFNumber(256)),
	})
	if err != nil {
		return nilSecKey, err
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	pkCF, err := newCFData(pk.Bytes())
	if err != nil {
		return nilSecKey, err
	}
	defer C.CFRelease(C.CFTypeRef(pkCF))

	var eRef C.CFErrorRef
	pkRef := C.SecKeyCreateWithData(pkCF, attrs, &eRef) //nolint:gocritic
	if err := goError(eRef); err != nil {
		return nilSecKey, err
	}

	return pkRef, nil
}
