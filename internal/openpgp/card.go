// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	iso "cunicu.li/hawkes/internal/iso7816"
	"github.com/ebfe/scard"
)

var (
	errResponseTooLarge = errors.New("expected data response too large")
	errCommandTooLarge  = errors.New("command data too large")
)

type Card struct {
	card *scard.Card

	longer int
}

func NewCard(sc *scard.Card) (c *Card, err error) {
	c = &Card{
		card: sc,
	}

	if err = sc.Reconnect(scard.ShareShared, scard.ProtocolAny, scard.ResetCard); err != nil {
		return nil, fmt.Errorf("failed to reset card: %w", err)
	}

	if err = c.Select(); err != nil {
		return nil, fmt.Errorf("failed to select applet: %w", err)
	}

	return c, nil
}

// sendAPDU sends an APDU 7816-4 with extended length
func (c *Card) communicate(cla byte, ins iso.Instruction, p1, p2 byte, data []byte, lenExpResp int) (resp []byte, err error) {
	lenData := len(data)

	apdu := []byte{cla, byte(ins), p1, p2}

	switch {
	case lenData < apduShort && lenExpResp <= apduShort:
		// Standard APDU : Lc 1 byte : short command and short response

		apdu = append(apdu, byte(lenData))
		apdu = append(apdu, data...)
	case lenData < apduLong:
		// Extended APDU : Lc 3 bytes : extended command and extended response

		apdu = append(apdu, 0, byte(lenData>>8), byte(lenData&0xff))
		apdu = append(apdu, data...)
	default:
		return nil, errCommandTooLarge
	}

	if lenExpResp > 0 {
		// Le present
		switch {
		case lenExpResp < apduShort:
			// Le fixed and short
			apdu = append(apdu, byte(lenExpResp))
		case lenExpResp == apduShort:
			// Le short : max response len 255 bytes
			apdu = append(apdu, 0)
		case lenExpResp < apduLong:
			// Le fixed and long
			apdu = append(apdu, byte(lenExpResp>>8), byte(lenExpResp&0xff))
		case lenExpResp == apduLong:
			// Le long : max response len 65535 bytes
			apdu = append(apdu, 0, 0)
		default:
			return nil, errResponseTooLarge
		}
	}

	// logger.debug(
	//     f" Sending 0x{apdu_header[1]:X} command with {len_data} bytes data"
	// )
	// if exp_resp_len > 0:
	//     logger.debug(f"  with Le={exp_resp_len}")
	// logger.debug(f"-> {toHexString(apdu)}")
	// t_env = time.time()

	log.Printf("-> Sending command APDU: %s", hex.EncodeToString(apdu))

	if resp, err = c.card.Transmit(apdu); err != nil {
		return nil, err
	}

	log.Printf("<- Received response APDU: %s", hex.EncodeToString(resp))

	resp, sw1, sw2 := decodeResponse(resp)

	// t_ans = (time.time() - t_env) * 1000
	// logger.debug(
	//     " Received %i bytes data : SW 0x%02X%02X - duration: %.1f ms"
	//     % (len(data), sw_byte1, sw_byte2, t_ans)
	// )
	// if len(data) > 0:
	//     logger.debug(f"<- {toHexString(data)}")

	for sw1 == 0x61 {
		var respRem []byte
		//     t_env = time.time()

		apdu = []byte{0x00, 0xc0, 0x00, 0x00, 0x00}
		if respRem, err = c.card.Transmit(apdu); err != nil {
			return nil, err
		}

		respRem, sw1, sw2 = decodeResponse(respRem)

		//     t_ans = (time.time() - t_env) * 1000
		//     logger.debug(
		//         " Received remaining %i bytes : 0x%02X%02X - duration: %.1f ms"
		//         % (len(datacompl), sw_byte1, sw_byte2, t_ans)
		//     )
		//     logger.debug(f"<- {toHexString(datacompl)}")

		resp = append(resp, respRem...)
	}

	if sw1 != 0x90 || sw2 != 0x00 {
		return nil, Error(uint16(sw1)<<8 | uint16(sw2))
	}

	return resp, nil
}

func (c *Card) send(cla byte, ins iso.Instruction, p1, p2 byte, data []byte) error {
	_, err := c.communicate(cla, ins, p1, p2, data, 0)
	return err
}

// See: OpenPGP Smart Card Application - Section 7.2.5 SELECT DATA
func (c *Card) selectData(t iso.Tag, idx byte) error {
	data := iso.EncodeTLV(0x60,
		iso.EncodeTLV(0x5c, t.Bytes()))

	return c.send(0x00, insSelectData, idx, 0x04, data)
}

// See: OpenPGP Smart Card Application - Section 7.2.6 GET DATA
func (c *Card) getData(t iso.Tag) ([]byte, error) {
	// logger.debug(f"Read Data {data_hex} in 0x{filehex}")

	p1 := byte(t >> 8)
	p2 := byte(t)

	return c.communicate(0x00, iso.InsGetData, p1, p2, nil, c.longer)
}

// See: OpenPGP Smart Card Application - Section 7.2.7 GET NEXT DATA
func (c *Card) getNextData(t iso.Tag) ([]byte, error) {
	return c.communicate(0x00, insGetNextData, 0x7f, 0x21, nil, c.longer)
}

func (c *Card) getDataIndex(t iso.Tag, i byte) ([]byte, error) {
	if err := c.selectData(t, i); err != nil {
		return nil, err
	}

	return c.getData(t)
}

func (c *Card) getAllData(t iso.Tag) (datas [][]byte, err error) {
	var data []byte
	getData := c.getData

	for {
		data, err = getData(t)
		if err != nil {
			var gerr Error
			if errors.As(err, &gerr) {
				break
			}

			return nil, err
		}

		getData = c.getNextData
		datas = append(datas, data)
	}

	return datas, nil
}

// See: OpenPGP Smart Card Application - Section 7.2.8 PUT DATA
func (c *Card) putData(t iso.Tag, data []byte) error {
	p1 := byte(t >> 8)
	p2 := byte(t)

	return c.send(0x00, iso.InsPutData, p1, p2, data)
}

// See: OpenPGP Smart Card Application - Section 7.2.1 SELECT
func (c *Card) Select() error {
	return c.send(0x00, iso.InsSelect, 0x04, 0x00, appID)
}

func (c *Card) GetApplicationRelatedData() (ar ApplicationRelated, err error) {
	resp, err := c.getData(tagApplicationRelated)
	if err != nil {
		return ar, err
	}

	return ar, ar.Decode(resp)
}

func (c *Card) GetSecuritySupportTemplate() (sst SecuritySupportTemplate, err error) {
	resp, err := c.getData(tagSecuritySupportTemplate)
	if err != nil {
		return sst, err
	}

	return sst, sst.Decode(resp)
}

func (c *Card) GetCardholder() (ch Cardholder, err error) {
	resp, err := c.getData(tagCardholderRelated)
	if err != nil {
		return ch, err
	}

	return ch, ch.Decode(resp)
}

// See: OpenPGP Smart Card Application - Section 7.2.15 GET CHALLENGE
func (c *Card) GetChallenge(cnt int) ([]byte, error) {
	return c.communicate(0x00, iso.InsGetChallenge, 0x00, 0x00, nil, cnt)
}

// See: OpenPGP Smart Card Application - Section 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE
func (c *Card) Sign(data []byte) ([]byte, error) {
	return nil, nil // TODO
}

// See: OpenPGP Smart Card Application - Section 7.2.12 PSO: ENCIPHER
func (c *Card) Encipher(data []byte) ([]byte, error) {
	return nil, nil // TODO
}

// See: OpenPGP Smart Card Application - Section 7.2.11 PSO: DECIPHER
func (c *Card) Decipher(data []byte) ([]byte, error) {
	return nil, nil // TODO
}

// See: OpenPGP Smart Card Application - Section 7.2.11 PSO: DECIPHER
func (c *Card) CalculateSharedSecret(pk []byte) ([]byte, error) {
	data := iso.EncodeTLV(tagCipher,
		iso.EncodeTLV(tagPublicKey,
			iso.EncodeTLV(tagExternalPublicKey, pk)))

	return c.communicate(0x00, iso.InsPerformSecurityOperation, 0x80, 0x86, data, c.longer)
}

// See: OpenPGP Smart Card Application - Section 7.2.14 GENERATE ASYMMETRIC KEY PAIR
func (c *Card) GenerateKeyPair() error {
	return nil // TODO
}

// See: OpenPGP Smart Card Application - Section 7.2.16 TERMINATE DF
func (c *Card) terminate() error {
	// TODO: Check if supported in Life Cycle Status indicator in Historical bytes
	return c.send(0x00, iso.InsTerminateDF, 0x00, 0x00, nil)
}

// See: OpenPGP Smart Card Application - Section 7.2.17 ACTIVATE FILE
func (c *Card) activate() error {
	return c.send(0x00, iso.InsActivateFile, 0x00, 0x00, nil)
}

// See: OpenPGP Smart Card Application - Section
func (c *Card) FactoryReset() error {
	// TODO: Check if supported in Life Cycle Status indicator in Historical bytes

	if err := c.terminate(); err != nil {
		return err
	}

	return c.activate()
}

// See: OpenPGP Smart Card Application - Section 7.2.18 MANAGE SECURITY ENVIRONMENT
func (c *Card) ManageSecurityEnvironment(crt byte, slot Slot) error {
	// TODO: Check if MSE is supported in extended capabilities

	keyRef := []byte{0x83, 0x01, byte(slot)}
	return c.send(0x00, iso.InsManageSecurityEnvironment, 0x41, crt, keyRef)
}

// See: OpenPGP Smart Card Application - Section 7.2.2 VERIFY
func (c *Card) VerifyPassword(pwType byte, pw string) (err error) {
	if len(pw) == 0 {
		return c.send(0x00, iso.InsVerify, 0x00, pwType, nil)
	} else {
		return c.send(0x00, iso.InsVerify, 0xff, pwType, []byte(pw))
	}
}

// See: OpenPGP Smart Card Application - Section 7.2.3 CHANGE REFERENCE DATA
func (c *Card) ChangePassword(pwType byte, pwActual, pwNew string) error {
	switch pwType {
	case PW1:
		if len(pwNew) < 6 {
			return errInvalidLength
		}
	case PW3:
		if len(pwNew) < 8 {
			return errInvalidLength
		}
	}

	return c.send(0x00, iso.InsChangeReferenceData, 0x00, pwType, []byte(pwActual+pwNew))
}

// See: OpenPGP Smart Card Application - Section 7.2.4 RESET RETRY COUNTER
func (c *Card) ResetRetryCounter(pw string) error {
	if len(pw) < 6 {
		return errInvalidLength
	}

	return c.send(0x00, iso.InsResetRetryCounter, 0x02, PW1, []byte(pw))
}

// See: OpenPGP Smart Card Application - Section 7.2.4 RESET RETRY COUNTER
func (c *Card) ResetRetryCounterWithResetCode(pw, rc string) error {
	if len(pw) < 6 {
		return errInvalidLength
	}

	return c.send(0x00, iso.InsResetRetryCounter, 0x00, PW1, []byte(rc+pw))
}

func decodeResponse(resp []byte) (data []byte, sw1 byte, sw2 byte) {
	lenResp := len(resp)

	sw1 = resp[lenResp-2]
	sw2 = resp[lenResp-1]
	data = resp[:lenResp-2]

	return data, sw1, sw2
}
