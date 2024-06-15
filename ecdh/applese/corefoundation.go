// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-FileCopyrightText: 2023 Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

//nolint:gci
package applese

import (
	"errors"
	"fmt"
	"unsafe"
)

/*
#cgo LDFLAGS: -framework CoreFoundation

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
*/
import "C"

var errUnknownErrorType = errors.New("unknown error type")

const (
	nilCFData       C.CFDataRef       = 0
	nilCFString     C.CFStringRef     = 0
	nilCFDictionary C.CFDictionaryRef = 0
	nilCFError      C.CFErrorRef      = 0
	nilCFType       C.CFTypeRef       = 0
)

var errCreating = errors.New("error creating")

func newCFData(d []byte) (C.CFDataRef, error) {
	p := (*C.uchar)(C.CBytes(d))
	defer C.free(unsafe.Pointer(p))

	ref := C.CFDataCreate(C.kCFAllocatorDefault, p, C.CFIndex(len(d)))
	if ref == nilCFData {
		return ref, fmt.Errorf("%w CFData", errCreating)
	}

	return ref, nil
}

func newCFNumber(u int32) C.CFNumberRef {
	sint := C.SInt32(u)
	p := unsafe.Pointer(&sint)
	return C.CFNumberCreate(C.kCFAllocatorDefault, C.kCFNumberSInt32Type, p)
}

func newCFString(s string) (C.CFStringRef, error) {
	p := C.CString(s)
	defer C.free(unsafe.Pointer(p))

	ref := C.CFStringCreateWithCString(C.kCFAllocatorDefault, p, C.kCFStringEncodingUTF8)
	if ref == nilCFString {
		return ref, fmt.Errorf("%w CFString", errCreating)
	}
	return ref, nil
}

func newCFDictionary(m map[C.CFTypeRef]C.CFTypeRef) (C.CFDictionaryRef, error) {
	var (
		keys []unsafe.Pointer
		vals []unsafe.Pointer
	)

	for k, v := range m {
		keys = append(keys, unsafe.Pointer(k)) //nolint:unsafeptr
		vals = append(vals, unsafe.Pointer(v)) //nolint:unsafeptr
	}

	return C.CFDictionaryCreate(C.kCFAllocatorDefault, &keys[0], &vals[0], C.CFIndex(len(m)),
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks), nil //nolint:gocritic
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

		return osStatusError(-v)

	case C.CFErrorRef:
		if v == nilCFError {
			return nil
		}

		cfErr := &cfRefError{
			code: int(C.CFErrorGetCode(v)),
		}

		if errStrRef := C.CFErrorCopyDescription(v); errStrRef != nilCFString {
			defer C.CFRelease(C.CFTypeRef(errStrRef))
			cfErr.desc = cfStringToString(errStrRef)
		}

		return cfErr
	}

	return fmt.Errorf("%w: %T", errUnknownErrorType, e)
}

type (
	osStatusError int
	cfRefError    struct {
		code int
		desc string
	}
)

func (e osStatusError) Error() string {
	if errStrRef := C.SecCopyErrorMessageString(C.int(-e), nil); errStrRef != nilCFString {
		defer C.CFRelease(C.CFTypeRef(errStrRef))
		return fmt.Sprintf("%s (%d)", cfStringToString(errStrRef), e)
	}

	return fmt.Sprintf("OSStatus (%d)", e)
}

func (e cfRefError) Error() string {
	if e.desc != "" {
		return fmt.Sprintf("%s (%d)", e.desc, e.code)
	}

	return fmt.Sprintf("CFError (%d)", e.code)
}

func cfStringToString(ref C.CFStringRef) string {
	return C.GoString(C.CFStringGetCStringPtr(ref, C.kCFStringEncodingUTF8))
}

func cfDataToBytes(data C.CFDataRef) []byte {
	return C.GoBytes(
		unsafe.Pointer(
			C.CFDataGetBytePtr(data),
		),
		C.int(C.CFDataGetLength(data)),
	)
}

var errKeyNotFound = osStatusError(25300)
