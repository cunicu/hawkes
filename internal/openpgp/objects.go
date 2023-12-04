// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"time"

	iso "cunicu.li/hawkes/internal/iso7816"
)

var (
	errInvalidLength   = errors.New("invalid length")
	errInvalidResponse = errors.New("invalid response")
)

type UserInteractionFlag struct {
	Requirement byte
	Feature     byte
}

func (uif *UserInteractionFlag) Decode(b []byte) error {
	if len(b) != 2 {
		return errInvalidLength
	}

	uif.Requirement = b[0]
	uif.Feature = b[1]

	return nil
}

type AlgorithmAttributes struct {
	Algorithm

	more []byte
}

func (a *AlgorithmAttributes) Decode(b []byte) error {
	if len(b) < 1 {
		return errInvalidLength
	}

	a.Algorithm = Algorithm(b[0])
	a.more = b[1:]

	return nil
}

func (a *AlgorithmAttributes) String() string {
	return "" // TODO
}

type Fingerprint [20]byte

type KeyInfo struct {
	Reference      byte
	Status         byte
	AlgAttrs       AlgorithmAttributes
	Fingerprint    []byte
	FingerprintCA  []byte
	GenerationTime time.Time
	UIF            UserInteractionFlag
}

type HistoricalBytes struct {
	CategoryIndicator byte
	StatusIndicator   []byte

	Caps struct {
		CmdChaining       bool // Command chaining
		ExtLen            bool // Extended Lc and Le fields
		ExtLenInfoinEFATR bool // Extended Length Information in EF.ATR/INFO
		LogicalChanNum    bool
	}

	CardService struct {
		AppSelectionFullDF bool // Application Selection by full DF name (AID)
		AppSelectPartialDF bool // Application Selection by partial DF name
		EfDirDOsAvailable  bool // DOs available in EF.DIR

		// EF.DIR and EF.ATR/INFO access services
		// by the GET DATA command (BER-TLV)
		// Should be set to 010, if Extended Length is
		// supported

		MF bool // Card with MF
	}
}

func (h *HistoricalBytes) Decode(b []byte) (err error) {
	h.CategoryIndicator = b[0]

	switch h.CategoryIndicator {
	case 0x10:
		// Not supported

	case 0x00:
		lb := len(b)
		h.StatusIndicator = b[lb-3:]
		b = b[:lb-3]
		fallthrough

	case 0x80:
		var t iso.CompactTag
		// var v []byte

		for len(b) > 0 {
			if t, _, b, err = iso.DecodeCompactTLV(b); err != nil {
				return err
			}

			switch t {
			case ctagCaps:

			case ctagCardService:
			}
		}

	default:
	}

	return nil
}

type ApplicationRelated struct {
	AID             ApplicationIdentifier
	HistoricalBytes HistoricalBytes

	LengthInfo     ExtendedLengthInfo
	Capabilities   ExtendedCapabilities
	Features       GeneralFeatures
	PasswordStatus PasswordStatus

	Keys [4]KeyInfo
}

func (ar *ApplicationRelated) Decode(b []byte) (err error) {
	var v, w, x []byte
	var t iso.Tag

	if t, v, _, err = iso.DecodeTLV(b); err != nil {
		return err
	} else if t != tagApplicationRelated || !t.IsConstructed() {
		return errInvalidResponse
	}

	for len(v) > 0 {
		if t, w, v, err = iso.DecodeTLV(v); err != nil {
			return errInvalidLength
		}

		switch t {
		case tagAID:
			if err := ar.AID.Decode(w); err != nil {
				return fmt.Errorf("failed to decode application identifier: %w", err)
			}

		case tagHistoricalBytes:
			if err := ar.HistoricalBytes.Decode(w); err != nil {
				return fmt.Errorf("failed to decode historical bytes: %w", err)
			}

		case tagGeneralFeatureManagement:
			if err := ar.Features.Decode(w); err != nil {
				return fmt.Errorf("failed to decode general features: %w", err)
			}

		case tagDiscretionaryDOs:
			for len(w) > 0 {
				if t, x, w, err = iso.DecodeTLV(w); err != nil {
					return errInvalidLength
				}

				switch t {
				case tagExtLenInfo:
					if err := ar.LengthInfo.Decode(x); err != nil {
						return fmt.Errorf("failed to decode extended length information: %w", err)
					}

				case tagExtCaps:
					if err := ar.Capabilities.Decode(x); err != nil {
						return fmt.Errorf("failed to decode extended capabilities: %w", err)
					}

				case tagAlgAttrsSign:
					if err := ar.Keys[SlotSign].AlgAttrs.Decode(x); err != nil {
						return fmt.Errorf("failed to decode sign key attrs: %w", err)
					}
				case tagAlgAttrsDecrypt:
					if err := ar.Keys[SlotDecrypt].AlgAttrs.Decode(x); err != nil {
						return fmt.Errorf("failed to decode decrypt key attrs: %w", err)
					}
				case tagAlgAttrsAuthn:
					if err := ar.Keys[SlotAuthn].AlgAttrs.Decode(x); err != nil {
						return fmt.Errorf("failed to decode authentication key attrs: %w", err)
					}
				case tagAlgAttrsAttest:
					if err := ar.Keys[SlotAttest].AlgAttrs.Decode(x); err != nil {
						return fmt.Errorf("failed to decode attestation key attrs: %w", err)
					}
				case tagUIFSign:
					if err := ar.Keys[SlotSign].UIF.Decode(x); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}
				case tagUIFAuthn:
					if err := ar.Keys[SlotAuthn].UIF.Decode(x); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagUIFDecrypt:
					if err := ar.Keys[SlotDecrypt].UIF.Decode(x); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagUIFAttest:
					if err := ar.Keys[SlotAttest].UIF.Decode(x); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagPasswordStatus:
					if err := ar.PasswordStatus.Decode(x); err != nil {
						return fmt.Errorf("failed to decode password status: %w", err)
					}

				case tagFP:
					if len(x) < 60 {
						return errInvalidLength
					}

					ar.Keys[SlotSign].Fingerprint = x[0:20]
					ar.Keys[SlotDecrypt].Fingerprint = x[20:40]
					ar.Keys[SlotAuthn].Fingerprint = x[40:60]

				case tagFPAttest:
					if len(x) < 20 {
						return errInvalidLength
					}

					ar.Keys[SlotAttest].Fingerprint = x[0:20]

				case tagCAFP:
					if len(x) < 60 {
						return errInvalidLength
					}
					ar.Keys[SlotSign].FingerprintCA = x[0:20]
					ar.Keys[SlotDecrypt].FingerprintCA = x[20:40]
					ar.Keys[SlotAuthn].FingerprintCA = x[40:60]
				case tagCAFPAttest:
					if len(x) < 20 {
						return errInvalidLength
					}

					ar.Keys[SlotAttest].FingerprintCA = x[0:20]

				case tagGenTime:
					if len(x) < 12 {
						return errInvalidLength
					}

					ar.Keys[SlotSign].GenerationTime = decodeTime(x[0:])
					ar.Keys[SlotDecrypt].GenerationTime = decodeTime(x[4:])
					ar.Keys[SlotAuthn].GenerationTime = decodeTime(x[8:])

				case tagGenTimeAttest:
					if len(x) < 4 {
						return errInvalidLength
					}

					ar.Keys[SlotAttest].GenerationTime = decodeTime(x[0:])

				case tagKeyInfo:
					for i := 0; i < len(x)/2; i++ {
						ar.Keys[i].Reference = x[i*2+0]
						ar.Keys[i].Status = x[i*2+1]
					}

				default:
					slog.Warn("Received unknown tag",
						slog.String("do", "discretionary objects"),
						slog.Any("tag", t))
				}
			}

		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "application related"),
				slog.Any("tag", t))
		}
	}

	return nil
}

type PasswordStatus struct {
	ValidityPW1 uint8

	LengthPW1 uint8
	LengthRC  uint8
	LengthPW3 uint8

	AttemptsPW1 uint8
	AttemptsRC  uint8
	AttemptsPW3 uint8
}

func (ps *PasswordStatus) Decode(b []byte) error {
	if len(b) != 7 {
		return errInvalidLength
	}

	ps.ValidityPW1 = b[0]
	ps.LengthPW1 = b[1]
	ps.LengthRC = b[2]
	ps.LengthPW3 = b[3]
	ps.AttemptsPW1 = b[4]
	ps.AttemptsRC = b[5]
	ps.AttemptsPW3 = b[6]

	return nil
}

type ExtendedCapabilities struct {
	SecureMessaging          bool
	GetChallenge             bool
	KeyImport                bool
	PasswordStatusChangeable bool
	PrivateDO                bool
	AlgAttrsChangeable       bool
	EncDecAES                bool
	KdfDO                    bool
	AlgSecureMessaging       byte
	MaxLenChallenge          uint16
	MaxLenCardholderCert     uint16
	MaxLenSpecialDO          uint16
	Pin2BlockFormat          byte
	CommandMSE               byte
}

func (ec *ExtendedCapabilities) Decode(b []byte) error {
	if len(b) != 10 {
		return errInvalidLength
	}

	ec.SecureMessaging = b[0]&(1<<7) != 0
	ec.GetChallenge = b[0]&(1<<6) != 0
	ec.KeyImport = b[0]&(1<<5) != 0
	ec.PasswordStatusChangeable = b[0]&(1<<4) != 0
	ec.PrivateDO = b[0]&(1<<3) != 0
	ec.AlgAttrsChangeable = b[0]&(1<<2) != 0
	ec.EncDecAES = b[0]&(1<<1) != 0
	ec.KdfDO = b[0]&(1<<0) != 0

	ec.AlgSecureMessaging = b[1]
	ec.MaxLenChallenge = binary.BigEndian.Uint16(b[2:])
	ec.MaxLenCardholderCert = binary.BigEndian.Uint16(b[4:])
	ec.MaxLenSpecialDO = binary.BigEndian.Uint16(b[6:])
	ec.Pin2BlockFormat = b[8]
	ec.CommandMSE = b[9]

	return nil
}

type Cardholder struct {
	Name     string
	Language string
	Sex      Sex
}

func (ch *Cardholder) Decode(b []byte) (err error) {
	var t iso.Tag
	var v, w []byte

	if t, v, _, err = iso.DecodeTLV(b); err != nil {
		return err
	} else if t != tagCardholderRelated || !t.IsConstructed() {
		return errInvalidResponse
	}

	for len(v) > 0 {
		if t, w, v, err = iso.DecodeTLV(v); err != nil {
			return err
		}

		switch t {
		case tagName:
			ch.Name = string(w)
		case tagSex:
			if len(w) < 1 {
				return errInvalidLength
			}
			ch.Sex = Sex(w[0])
		case tagLanguage:
			ch.Language = string(w)
		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "application related"),
				slog.Any("tag", t))
		}
	}

	return nil
}

type SecuritySupportTemplate struct {
	SignatureCounter [3]byte
	CardHolderCerts  [3][]byte
}

func (sst *SecuritySupportTemplate) Decode(b []byte) (err error) {
	var v, w []byte
	var t iso.Tag

	if t, v, _, err = iso.DecodeTLV(b); err != nil {
		return err
	} else if t != tagSecuritySupportTemplate || !t.IsConstructed() {
		return errInvalidResponse
	}

	for len(v) > 0 {
		if t, w, v, err = iso.DecodeTLV(v); err != nil {
			return errInvalidLength
		}

		switch t {
		case tagSignatureCounter:
			copy(sst.SignatureCounter[:], w)

		case tagCert:
			log.Println(hex.EncodeToString(w))

		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "application related"),
				slog.Any("tag", t))
		}
	}

	return nil
}

type GeneralFeatures struct {
	Display     bool
	Bio         bool
	Button      bool
	KeyPad      bool
	LED         bool
	Speaker     bool
	Mic         bool
	Touchscreen bool
}

func (f *GeneralFeatures) Decode(b []byte) error {
	if len(b) != 3 {
		return errInvalidLength
	}

	f.Display = b[0]&(1<<7) != 0
	f.Bio = b[0]&(1<<6) != 0
	f.Button = b[0]&(1<<5) != 0
	f.KeyPad = b[0]&(1<<4) != 0
	f.LED = b[0]&(1<<3) != 0
	f.Speaker = b[0]&(1<<2) != 0
	f.Mic = b[0]&(1<<1) != 0
	f.Touchscreen = b[0]&(1<<0) != 0

	return nil
}

type ApplicationIdentifier struct {
	RID          RID
	Application  byte
	Version      [2]byte
	Serial       [4]byte
	Manufacturer uint16
	RFU          [2]byte
	SerialGPG    uint64
}

func (aid *ApplicationIdentifier) Decode(b []byte) error {
	if len(b) != 16 {
		return errInvalidLength
	}

	aid.RID = [5]byte(b[0:5])
	aid.Application = b[5]
	aid.Version = [2]byte(b[6:8])
	aid.Manufacturer = binary.BigEndian.Uint16(b[8:10])
	aid.Serial = [4]byte(b[10:14])
	aid.RFU = [2]byte(b[14:16])

	return nil
}

func (aid *ApplicationIdentifier) ManufacturerName() string {
	if manu, ok := manufacturers[aid.Manufacturer]; ok {
		return manu
	}

	return "unknown"
}

type ExtendedLengthInfo struct {
	MaxCommandLength  uint16
	MaxResponseLength uint16
}

func (li *ExtendedLengthInfo) Decode(b []byte) error {
	if len(b) != 8 {
		return errInvalidLength
	}

	li.MaxCommandLength = binary.BigEndian.Uint16(b[2:4])
	li.MaxResponseLength = binary.BigEndian.Uint16(b[6:8])

	return nil
}

func decodeTime(b []byte) time.Time {
	tsc := binary.BigEndian.Uint32(b)
	return time.Unix(int64(tsc), 0)
}
