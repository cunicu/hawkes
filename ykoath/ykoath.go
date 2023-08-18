// SPDX-FileCopyrightText: 2023 Joern Barthel
// SPDX-License-Identifier: Apache-2.0

// Package ykoath implements the Yubico OATH protocol
// for the Yubikey OATH-HOTP/TOTP hardware tokens
// https://developers.yubico.com/OATH/YKOATH_Protocol.html
package ykoath

import (
	"fmt"
	"strings"
	"time"

	"github.com/ebfe/scard"
	"github.com/pkg/errors"
)

type (
	tag         byte
	instruction byte
)

const HMACMinimumKeySize = 14

// TLV tags for credential data
const (
	tagName      tag = 0x71
	tagNameList  tag = 0x72
	tagKey       tag = 0x73
	tagChallenge tag = 0x74
	tagResponse  tag = 0x75
	tagTruncated tag = 0x76
	tagHOTP      tag = 0x77
	tagProperty  tag = 0x78
	tagVersion   tag = 0x79
	tagImf       tag = 0x7A
	tagAlgorithm tag = 0x7B
	tagTouch     tag = 0x7C
)

// Instruction bytes for commands
const (
	insList          instruction = 0xA1
	insSelect        instruction = 0xA4
	insPut           instruction = 0x01
	insDelete        instruction = 0x02
	insSetCode       instruction = 0x03
	insReset         instruction = 0x04
	insRename        instruction = 0x05
	insCalculate     instruction = 0xA2
	insValidate      instruction = 0xA3
	insCalculateAll  instruction = 0xA4
	insSendRemaining instruction = 0xA5
)

type card interface {
	Disconnect(scard.Disposition) error
	Transmit([]byte) ([]byte, error)
}

type context interface {
	Release() error
}

// OATH implements most parts of the TOTP portion of the YKOATH specification
// https://developers.yubico.com/OATH/YKOATH_Protocol.html
type OATH struct {
	Clock  func() time.Time
	Period time.Duration

	card    card
	context context
}

const (
	errFailedToConnect            = "failed to connect to reader"
	errFailedToDisconnect         = "failed to disconnect from reader"
	errFailedToEstablishContext   = "failed to establish context"
	errFailedToListReaders        = "failed to list readers"
	errFailedToListSuitableReader = "no suitable reader found (out of %d readers)"
	errFailedToReleaseContext     = "failed to release context"
	errFailedToTransmit           = "failed to transmit APDU"
	errUnknownTag                 = "unknown tag (%x)"
)

// New initializes a new OATH session
func New() (*OATH, error) {
	context, err := scard.EstablishContext()
	if err != nil {
		return nil, errors.Wrapf(err, errFailedToEstablishContext)
	}

	readers, err := context.ListReaders()
	if err != nil {
		return nil, errors.Wrapf(err, errFailedToListReaders)
	}

	for _, reader := range readers {
		if strings.Contains(strings.ToLower(reader), "yubikey") {

			card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)
			if err != nil {
				return nil, errors.Wrapf(err, errFailedToConnect)
			}

			return &OATH{
				Clock:   time.Now,
				Period:  30 * time.Second,
				card:    card,
				context: context,
			}, nil

		}
	}

	return nil, fmt.Errorf(errFailedToListSuitableReader, len(readers))
}

// Close terminates an OATH session
func (o *OATH) Close() error {
	if err := o.card.Disconnect(scard.LeaveCard); err != nil {
		return errors.Wrapf(err, errFailedToDisconnect)
	}

	if err := o.context.Release(); err != nil {
		return errors.Wrapf(err, errFailedToReleaseContext)
	}

	return nil
}

// send sends an APDU to the card
func (o *OATH) send(cla byte, ins instruction, p1, p2 byte, data ...[]byte) (tvs, error) {
	var (
		code    code
		results []byte
		send    = append([]byte{cla, byte(ins), p1, p2}, write(0x00, data...)...)
	)

	for {
		res, err := o.card.Transmit(send)
		if err != nil {
			return nil, errors.Wrapf(err, errFailedToTransmit)
		}

		code = res[len(res)-2:]
		results = append(results, res[0:len(res)-2]...)

		if code.IsMore() {
			send = []byte{0x00, 0xa5, 0x00, 0x00}
		} else if code.IsSuccess() {
			return read(results), nil
		} else {
			return nil, code
		}
	}
}
