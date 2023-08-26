// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-FileCopyrightText: 2023 Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package se

import "fmt"

func goError(e interface{}) error {
	if e == nil {
		return nil
	}

	switch v := e.(type) {
	case C.OSStatus:
		if v == 0 {
			return nil
		}
		return osStatusError{code: int(v)}

	case C.CFErrorRef:
		if v == nilCFError {
			return nil
		}

		code := int(C.CFErrorGetCode(v))
		if desc := C.CFErrorCopyDescription(v); desc != nilCFString {
			defer C.CFRelease(C.CFTypeRef(desc))

			if cstr := C.CFStringGetCStringPtr(desc, C.kCFStringEncodingUTF8); cstr != nil {
				str := C.GoString(cstr)

				return fmt.Errorf("CFError %d (%s)", code, str)
			}

		}
		return fmt.Errorf("CFError %d", code)
	}

	return fmt.Errorf("unknown error type %T", e)
}

type osStatusError struct {
	code int
}

func (oserr osStatusError) Error() string {
	return fmt.Sprintf("OSStatus %d", oserr.code)
}
