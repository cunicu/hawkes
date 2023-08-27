// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-FileCopyrightText: 2023 Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package se

/*
#cgo LDFLAGS: -framework Security

#include <Security/Security.h>
*/
import "C"

const (
	nilSecKey           C.SecKeyRef           = 0
	nilSecAccessControl C.SecAccessControlRef = 0
)
