// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-FileCopyrightText: 2023 Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package se

import (
	"fmt"
	"unsafe"
)

/*
#cgo LDFLAGS: -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
*/
import "C"

const (
	nilCFData       C.CFDataRef       = 0
	nilCFString     C.CFStringRef     = 0
	nilCFDictionary C.CFDictionaryRef = 0
	nilCFError      C.CFErrorRef      = 0
	nilCFType       C.CFTypeRef       = 0
)

func newCFData(d []byte) (C.CFDataRef, error) {
	p := (*C.uchar)(C.CBytes(d))
	defer C.free(unsafe.Pointer(p))

	ref := C.CFDataCreate(C.kCFAllocatorDefault, p, C.CFIndex(len(d)))
	if ref == nilCFData {
		return ref, fmt.Errorf("error creating CFData")
	}

	return ref, nil
}

func newCFString(s string) (C.CFStringRef, error) {
	p := C.CString(s)
	defer C.free(unsafe.Pointer(p))

	ref := C.CFStringCreateWithCString(C.kCFAllocatorDefault, p, C.kCFStringEncodingUTF8)
	if ref == nilCFString {
		return ref, fmt.Errorf("error creating CFString")
	}
	return ref, nil
}

func newCFDictionary(m map[C.CFTypeRef]C.CFTypeRef) (C.CFDictionaryRef, error) {
	var (
		keys []unsafe.Pointer
		vals []unsafe.Pointer
	)

	for k, v := range m {
		keys = append(keys, unsafe.Pointer(k))
		vals = append(vals, unsafe.Pointer(v))
	}

	ref := C.CFDictionaryCreate(C.kCFAllocatorDefault, &keys[0], &vals[0], C.CFIndex(len(m)),
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks)
	return ref, nil
}

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
