// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package handshake

import "io"

var _ io.ReadWriter = (*InProcessPipe)(nil)

type InProcessPipe struct {
	*io.PipeReader
	*io.PipeWriter
}

func NewInProcessPipe() (*InProcessPipe, *InProcessPipe) {
	rd1, wr1 := io.Pipe()
	rd2, wr2 := io.Pipe()

	c1 := &InProcessPipe{
		PipeReader: rd1,
		PipeWriter: wr2,
	}

	c2 := &InProcessPipe{
		PipeReader: rd2,
		PipeWriter: wr1,
	}

	return c1, c2
}
