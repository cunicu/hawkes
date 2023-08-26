// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-FileCopyrightText: 2023 Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package se

import (
	"errors"
	"fmt"
	"unsafe"
)

// GenerateKeyPair creates a key with the given label and tag.
// Returns public key raw data.
func GenerateKeyPair(label, tag string) ([]byte, error) {
	protection := C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
	flags := C.kSecAccessControlPrivateKeyUsage

	cfTag, err := newCFData([]byte(tag))
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	cfLabel, err := newCFString(label)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfLabel))

	var eref C.CFErrorRef
	access := C.SecAccessControlCreateWithFlags(
		C.kCFAllocatorDefault,
		C.CFTypeRef(protection),
		C.SecAccessControlCreateFlags(flags),
		&eref)

	if err := goError(eref); err != nil {
		C.CFRelease(C.CFTypeRef(eref))
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(access))

	privKeyAttrs, err := newCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrAccessControl):  C.CFTypeRef(access),
		C.CFTypeRef(C.kSecAttrApplicationTag): C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrIsPermanent):    C.CFTypeRef(C.kCFBooleanTrue),
	})
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(privKeyAttrs))

	attrs, err := newCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrLabel):       C.CFTypeRef(cfLabel),
		C.CFTypeRef(C.kSecAttrTokenID):     C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave),
		C.CFTypeRef(C.kSecAttrKeyType):     C.CFTypeRef(C.kSecAttrKeyTypeEC),
		C.CFTypeRef(C.kSecPrivateKeyAttrs): C.CFTypeRef(privKeyAttrs),
	})
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	privKey := C.SecKeyCreateRandomKey(attrs, &eref)
	if err := goError(eref); err != nil {
		C.CFRelease(C.CFTypeRef(eref))
		return nil, err
	}
	if privKey == nilSecKey {
		return nil, fmt.Errorf("error generating random private key")
	}
	defer C.CFRelease(C.CFTypeRef(privKey))

	publicKey := C.SecKeyCopyPublicKey(privKey)
	if publicKey == nilSecKey {
		return nil, fmt.Errorf("error extracting public key")
	}
	defer C.CFRelease(C.CFTypeRef(publicKey))

	keyAttrs := C.SecKeyCopyAttributes(publicKey)
	defer C.CFRelease(C.CFTypeRef(keyAttrs))

	publicKeyData := C.CFDataRef(C.CFDictionaryGetValue(keyAttrs, unsafe.Pointer(C.kSecValueData)))

	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(publicKeyData)),
		C.int(C.CFDataGetLength(publicKeyData)),
	), nil
}

// FindPublicKey returns the raw public key described by label and tag
// hash is the SHA1 of the key. Can be nil.
func FindPublicKey(label, tag string, hash []byte) ([]byte, error) {
	key, err := fetchSEPrivKey(label, tag, hash)
	if err == nil {
		defer C.CFRelease(C.CFTypeRef(key))
		return extractPubKey(key)
	}

	var oserr osStatusError
	if errors.As(err, &oserr) {
		if oserr.code == C.errSecItemNotFound {
			return nil, nil
		}
	}
	return nil, err
}

// SignWithKey signs arbitrary data pointed to by data with the key described by
// label and tag. Returns the signed data.
// hash is the SHA1 of the key. Can be nil.
func SignWithKey(label, tag string, hash, digest []byte) ([]byte, error) {
	key, err := fetchSEPrivKey(label, tag, hash)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(key))

	cfDigest, err := newCFData(digest)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfDigest))

	var eref C.CFErrorRef
	signature := C.SecKeyCreateSignature(key, C.kSecKeyAlgorithmECDSASignatureDigestX962, cfDigest, &eref)
	if err := goError(eref); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(signature))

	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(signature)),
		C.int(C.CFDataGetLength(signature)),
	), nil
}

// RemoveKey tries to delete a key identified by label, tag and hash.
// hash is the SHA1 of the key. Can be nil
// If hash is nil then all the keys that match the label and tag specified will
// be deleted.
// Returns true if the key was found and deleted successfully
func RemoveKey(label, tag string, hash []byte) (bool, error) {
	cfTag, err := newCFData([]byte(tag))
	if err != nil {
		return false, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	cfLabel, err := newCFString(label)
	if err != nil {
		return false, err
	}
	defer C.CFRelease(C.CFTypeRef(cfLabel))

	m := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):              C.CFTypeRef(C.kSecClassKey),
		C.CFTypeRef(C.kSecAttrKeyType):        C.CFTypeRef(C.kSecAttrKeyTypeEC),
		C.CFTypeRef(C.kSecAttrApplicationTag): C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrLabel):          C.CFTypeRef(cfLabel),
		C.CFTypeRef(C.kSecAttrKeyClass):       C.CFTypeRef(C.kSecAttrKeyClassPrivate),
	}

	if hash != nil {
		d, err := newCFData(hash)
		if err != nil {
			return false, nil
		}
		defer C.CFRelease(C.CFTypeRef(d))

		m[C.CFTypeRef(C.kSecAttrApplicationLabel)] = C.CFTypeRef(d)
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

func fetchSESecretKey(label, tag string, hash []byte) (C.SecKeyRef, error) {
	cfTag, err := newCFData([]byte(tag))
	if err != nil {
		return nilSecKey, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	cfLabel, err := newCFString(label)
	if err != nil {
		return nilSecKey, err
	}
	defer C.CFRelease(C.CFTypeRef(cfLabel))

	m := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):              C.CFTypeRef(C.kSecClassKey),
		C.CFTypeRef(C.kSecAttrKeyType):        C.CFTypeRef(C.kSecAttrKeyTypeEC),
		C.CFTypeRef(C.kSecAttrApplicationTag): C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrLabel):          C.CFTypeRef(cfLabel),
		C.CFTypeRef(C.kSecAttrKeyClass):       C.CFTypeRef(C.kSecAttrKeyClassPrivate),
		C.CFTypeRef(C.kSecReturnRef):          C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit):         C.CFTypeRef(C.kSecMatchLimitOne),
	}

	if hash != nil {
		d, err := newCFData(hash)
		if err != nil {
			return nilSecKey, err
		}
		defer C.CFRelease(C.CFTypeRef(d))

		m[C.CFTypeRef(C.kSecAttrApplicationLabel)] = C.CFTypeRef(d)
	}

	query, err := newCFDictionary(m)
	if err != nil {
		return nilSecKey, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var key C.CFTypeRef
	status := C.SecItemCopyMatching(query, &key)
	if err := goError(status); err != nil {
		return nilSecKey, err
	}

	return C.SecKeyRef(key), nil
}

func extractPublicKey(key C.SecKeyRef) ([]byte, error) {
	publicKey := C.SecKeyCopyPublicKey(key)
	defer C.CFRelease(C.CFTypeRef(publicKey))

	keyAttrs := C.SecKeyCopyAttributes(publicKey)
	defer C.CFRelease(C.CFTypeRef(keyAttrs))

	val := C.CFDataRef(C.CFDictionaryGetValue(keyAttrs, unsafe.Pointer(C.kSecValueData)))
	if val == nilCFData {
		return nil, fmt.Errorf("cannot extract public key")
	}

	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(val)),
		C.int(C.CFDataGetLength(val)),
	), nil
}
