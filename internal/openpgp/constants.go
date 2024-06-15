// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//nolint:unused,gochecknoglobals
package openpgp

import "cunicu.li/hawkes/internal/iso7816"

type RID [5]byte

var RidFSFE = [5]byte{0xD2, 0x76, 0x00, 0x01, 0x24}

const (
	AppIDOpenPGP = 0x01
)

type Slot byte

const (
	SlotSign Slot = iota
	SlotDecrypt
	SlotAuthn
	SlotAttest
)

const (
	PW1 byte = 0x81
	PW2 byte = 0x82
	PW3 byte = 0x83
)

const (
	insSelectData  iso7816.Instruction = 0xa5
	insGetNextData iso7816.Instruction = 0xcc
)

// Compact TLV tags used in historical bytes
const (
	ctagCountryCode   iso7816.CompactTag = 0x1 // ISO 7816-4 Section 8.1.1.2.1 Country or issuer indicator
	ctagIssuerID      iso7816.CompactTag = 0x2 // ISO 7816-4 Section 8.1.1.2.1 Country or issuer indicator
	ctagAID           iso7816.CompactTag = 0xf // ISO 7816-4 Section 8.1.1.2.2 Application identifier
	ctagCardService   iso7816.CompactTag = 0x3 // ISO 7816-4 Section 8.1.1.2.2 Application identifier
	ctagInitialAccess iso7816.CompactTag = 0x4 // ISO 7816-4 Section 8.1.1.2.4 Initial access data
	ctagIssuer        iso7816.CompactTag = 0x5 // ISO 7816-4 Section 8.1.1.2.5 Card issuer's data
	ctagPreIssuing    iso7816.CompactTag = 0x6 // ISO 7816-4 Section 8.1.1.2.6 Pre-issuing data
	ctagCaps          iso7816.CompactTag = 0x7 // ISO 7816-4 Section 8.1.1.2.7 Card capabilities
)

// Tags reference file objects
const (
	tagPrivateUse1 iso7816.Tag = 0x0101 // Optional DO for private use (binary)
	tagPrivateUse2 iso7816.Tag = 0x0102 // Optional DO for private use (binary)
	tagPrivateUse3 iso7816.Tag = 0x0103 // Optional DO for private use (binary)
	tagPrivateUse4 iso7816.Tag = 0x0104 // Optional DO for private use (binary)

	tagAID iso7816.Tag = 0x4f // Application identifier (AID), ISO 7816-4

	// Cardholder

	tagName      iso7816.Tag = 0x5b   // Name (according to ISO/IEC 7501-1)
	tagLoginData iso7816.Tag = 0x5e   // Login data
	tagLanguage  iso7816.Tag = 0x5f2d // Language preferences (according to ISO 639)
	tagSex       iso7816.Tag = 0x5f35 // Sex (according to ISO 5218)

	tagPublicKeyURL iso7816.Tag = 0x5f50 // Uniform resource locator (URL)

	// Historical bytes, Card service data and Card capabilities shall
	// be included, mandatory for the OpenPGP application.
	tagHistoricalBytes iso7816.Tag = 0x5f52

	tagExternalPublicKey iso7816.Tag = 0x86
	tagCipher            iso7816.Tag = 0xa6

	// Cardholder certificate (each for AUT, DEC and SIG)
	// These DOs are designed to store a certificate (e.g. X.509) for the keys in the card.
	// They can be used to identify the card in a client-server authentication,
	// where specific non-OpenPGP-certificates are needed, for S-MIME and other x.509 related functions.
	// The maximum length of the DOs is announced in Extended Capabilities.
	// The content should be TLV-constructed, but is out of scope of this specification.
	// The DOs are stored in the order AUT (1st occurrence), DEC (2nd occurrence) and SIG (3rd occurrence).
	// Storing the AUT certificate at first occurrence is for downward compatibility with older versions of this specification.
	tagCert iso7816.Tag = 0x7f21

	tagPublicKey iso7816.Tag = 0x7f49

	// Extended length information (ISO 7816-4)
	// with maximum number of bytes for command and response.
	tagExtLenInfo iso7816.Tag = 0x7f66

	// General feature management (optional)
	tagGeneralFeatureManagment iso7816.Tag = 0x7f74

	tagDiscretionaryDOs iso7816.Tag = 0x73 // Discretionary data objects

	tagExtCaps iso7816.Tag = 0xc0 // Extended Capabilities, Flag list

	// Algorithm attributes
	// 1 Byte Algorithm ID, according to RFC 4880/6637
	// further bytes depending on algorithm (e.g. length modulus and length exponent).

	tagAlgAttrsSign    iso7816.Tag = 0xc1 // Algorithm attributes signature
	tagAlgAttrsDecrypt iso7816.Tag = 0xc2 // Algorithm attributes decryption
	tagAlgAttrsAuthn   iso7816.Tag = 0xc3 // Algorithm attributes authentication
	tagAlgAttrsAttest  iso7816.Tag = 0xda // Reserved for Algorithm attributes Attestation key (Yubico)

	// PW Status Bytes (binary)
	// 1st byte: 00 = PW1 (no. 81) only valid for one
	// PSO:CDS command
	//  01 = PW1 valid for several PSO:CDS commands
	//
	// 2nd byte: max. length and format of PW1 (user)
	// Bit 1-7 = max. length
	// Bit 8 = 0 for UTF-8 or derived password
	//         1 for PIN block format 2
	///
	// 3rd byte: max. length of Resetting Code (RC) for PW1
	//
	// 4th byte: max. length and format of PW3 (admin), see 2nd byte for PW1
	//
	// Byte 5, 6, 7 (first byte for PW1, second byte for Resetting Code, third byte for PW3):
	// 		Error counter of PW1, RC and PW3.
	//		If 00, then the corresponding PW/RC is blocked.
	//		Incorrect usage decrements the counter, correct verification sets to default value = 03.
	tagPasswordStatus iso7816.Tag = 0xc4

	// Fingerprints (binary, 20 bytes (dec.)
	// each for Sig, Dec, Aut in that order),
	// zero bytes indicate a not defined private key.
	tagFP       iso7816.Tag = 0xc5
	tagFPAttest iso7816.Tag = 0xdb // Reserved for Fingerprint of Attestation key (Yubico)

	// List of CA-Fingerprints (binary, 20 bytes (dec.) each) of “Ultimately Trusted Keys”.
	// Zero bytes indicate a free entry.
	// May be used to verify Public Keys from servers.
	tagCAFP       iso7816.Tag = 0xc6
	tagCAFPAttest iso7816.Tag = 0xdc // Reserved for CA-Fingerprint of Attestation key (Yubico)

	// List of generation dates/times of key pairs, binary.
	// 4 bytes, Big Endian each for Sig, Dec and Aut.
	// Each value shall be seconds since Jan 1, 1970.
	// Default value is 00000000 (not specified).
	tagGenTime       iso7816.Tag = 0xcd
	tagGenTimeAttest iso7816.Tag = 0xdd // Reserved for generation date/time of Attestation key (Yubico)

	// Key Information
	// Every key is presented with its Key-Reference number
	// first (1 byte) and a second status byte.
	//  Byte 1-2: Key-Ref. and Status of the signature key
	//  Byte 3-4: Key-Ref. and Status of the decryption key
	//  Byte 5-6: Key-Ref. and Status of the authentication key
	//  Further bytes: Key-Ref. and Status of additional keys (optional)
	//
	// Values for the Status byte:
	//   00 = Key not present (not generated or imported)
	//   01 = Key generated by the card
	//   02 = Key imported into the card
	tagKeyInfo iso7816.Tag = 0xde

	// User Interaction Flag (UIF)
	// If not supported, DO is not available.
	// First byte =
	//   00: UIF disabled (default)
	//   01: UIF enabled
	//   02: UIF permanently enabled (not changeable with PUT DATA, optional)
	//   03/04: Reserved for caching modes (Yubico)
	// Second byte = Content from General feature management ('20' for button/keypad)

	tagUIFSign    iso7816.Tag = 0xd6 // UIF for PSO:CDS (optional)
	tagUIFDecrypt iso7816.Tag = 0xd7 // UIF for PSO:DEC (optional)
	tagUIFAuthn   iso7816.Tag = 0xd8 // UIF for PSO:AUT (optional)
	tagUIFAttest  iso7816.Tag = 0xd9 // Reserved for UIF for Attestation key and Generate Attestation command (Yubico)

	// Digital signature counter (counts usage of Compute Digital Signature command), binary, ISO 7816-4.
	tagSignatureCounter iso7816.Tag = 0x93

	tagKDF     iso7816.Tag = 0xf9 // KDF-DO, announced in Extended Capabilities (optional)
	tagAlgInfo iso7816.Tag = 0xfa // Algorithm Information, List of supported Algorithm attributes
	tagCertSM  iso7816.Tag = 0xfb // Reserved for a certificate used with secure messaging (e. g. SCP11b), optional
	tagCertAtt iso7816.Tag = 0xfc // Reserved for an Attestation Certificate (Yubico), optional

	tagGeneralFeatureManagement iso7816.Tag = 0x7f74

	// Constructed DOs

	tagApplicationRelated      iso7816.Tag = 0x6e // Application related data
	tagCardholderRelated       iso7816.Tag = 0x65 // Cardholder related data
	tagSecuritySupportTemplate iso7816.Tag = 0x7a // Security support template
)

type Algorithm byte

const (
	AlgRSAEncSign Algorithm = 1
	AlgRSAEnc     Algorithm = 2
	AlgRSASign    Algorithm = 3
	AlgElgamal    Algorithm = 16
	AlgDSA        Algorithm = 17
	AlgECDH       Algorithm = 18
	AlgECDSA      Algorithm = 19
)

func (a Algorithm) String() string {
	switch a {
	case AlgRSAEncSign:
		return "RSAEncSign"
	case AlgRSAEnc:
		return "RSAEnc"
	case AlgRSASign:
		return "RSASign"
	case AlgElgamal:
		return "Elgamal"
	case AlgDSA:
		return "DSA"
	case AlgECDH:
		return "ECDH"
	case AlgECDSA:
		return "ECDSA"
	}

	return "Unknown"
}

type Sex byte

const (
	SexUnknown       Sex = '0'
	SexMale          Sex = '1'
	SexFemale        Sex = '2'
	SexNotApplicable Sex = '9'
)

func (s Sex) String() string {
	switch s {
	case SexMale:
		return "Male"
	case SexFemale:
		return "Female"
	case SexNotApplicable:
		return "Not Applicable"
	case SexUnknown:
		return "Unknown"
	}

	return ""
}

const (
	apduShort = 256
	apduLong  = 65536
)

var (
	appID = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}

	eccKeyTypes = map[string]string{
		"2A8648CE3D030107":     "nistp256",
		"2B2403030208010107":   "brainpoolP256r1",
		"2B240303020801010B":   "brainpoolP384r1",
		"2B240303020801010D":   "brainpoolP512r1",
		"2B8104000A":           "secp256k1",
		"2B81040022":           "nistp384",
		"2B81040023":           "nistp521",
		"2B060104019755010501": "x25519",
		"2B06010401DA470F01":   "ed25519",
		"2B656F":               "x448",
		"2B6571":               "ed448",
	}

	// From: https://github.com/gpg/gnupg/blob/9e4d52223945d677c1ffcb0e20dae48299e9aae1/scd/app-openpgp.c#L293
	manufacturers = map[uint16]string{
		0x0001: "PPC Card Systems",
		0x0002: "Prism",
		0x0003: "OpenFortress",
		0x0004: "Wewid",
		0x0005: "ZeitControl",
		0x0006: "Yubico",
		0x0007: "OpenKMS",
		0x0008: "LogoEmail",
		0x0009: "Fidesmo",
		0x000A: "VivoKey",
		0x000B: "Feitian Technologies",
		0x000D: "Dangerous Things",
		0x000E: "Excelsecu",
		0x000F: "Nitrokey",
		0x002A: "Magrathea",
		0x0042: "GnuPG e.V.",
		0x1337: "Warsaw Hackerspace",
		0x2342: "warpzone",                  // hackerspace Muenster
		0x4354: "Confidential Technologies", // cotech.de
		0x5343: "SSE Carte à puce",
		0x5443: "TIF-IT e.V.",
		0x63AF: "Trustica",
		0xBA53: "c-base e.V.",
		0xBD0E: "Paranoidlabs",
		0xCA05: "Atos CardOS",
		0xF1D0: "CanoKeys",
		0xF517: "FSIJ",
		0xF5EC: "F-Secure",

		0x2C97: "Ledger",
		0xAFAF: "ANSSI",
	}
)
