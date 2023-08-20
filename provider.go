// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package skes

import "context"

type Secret [32]byte

type Provider interface {
	Secret(ctx context.Context) (Secret, error)
}
