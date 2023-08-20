// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package skes

type (
	PublicKey  []byte
	CipherText []byte
)

type SecretEncrypter interface {
	Encrypt(ss Secret, pk PublicKey) (ct CipherText, err error)
}

type SecretDecrypter interface {
	PublicKey() PublicKey
	Decrypt(ct CipherText) (ss Secret, err error)
}

type Communicator interface {
	Send(msg any) error
	Receive() (any, error)
}

type Initiator struct {
	dec  SecretDecrypter
	comm Communicator
}

func NewInitiator(comm Communicator, dec SecretDecrypter) *Initiator {
	return &Initiator{
		comm: comm,
		dec:  dec,
	}
}

func (i *Initiator) Secret() (Secret, error) {
	return Secret{}, nil
}

type Responder struct {
	enc  SecretEncrypter
	comm Communicator
}

func NewResponder(comm Communicator, enc SecretEncrypter) *Responder {
	return &Responder{
		comm: comm,
		enc:  enc,
	}
}

func (r *Responder) Secret() (Secret, error) {
	return Secret{}, nil
}
