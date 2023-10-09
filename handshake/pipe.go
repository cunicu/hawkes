// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package handshake

import "io"

var _ io.ReadWriter = (*InprocessPipe)(nil)

type InprocessPipe struct {
	*io.PipeReader
	*io.PipeWriter
}

func NewInprocessPipe() (*InprocessPipe, *InprocessPipe) {
	rd1, wr1 := io.Pipe()
	rd2, wr2 := io.Pipe()

	c1 := &InprocessPipe{
		PipeReader: rd1,
		PipeWriter: wr2,
	}

	c2 := &InprocessPipe{
		PipeReader: rd2,
		PipeWriter: wr1,
	}

	return c1, c2
}
