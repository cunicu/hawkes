// SPDX-FileCopyrightText: 2023 Steffen Vogel
// SPDX-License-Identifier: Apache-2.0

package handshake

import "context"

// A SecretProvider represents a single cryptographic key accessed through a Provider
type Handshake interface {
	Secret(ctx context.Context) (Secret, error)
}

type Secret []byte
