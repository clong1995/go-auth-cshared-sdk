package auth

/*
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/windows -lauth
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/linux -lauth
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/macos -lauth
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/macos -lauth

#include <stdlib.h>
#include "auth.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

var (
	ErrAccessID = errors.New("auth: AccessID failed")
	ErrAuth     = errors.New("auth: Auth failed")
	ErrCheck    = errors.New("auth: Check failed")
	ErrSign     = errors.New("auth: Sign failed")

	ErrDataTooLarge = errors.New("auth: data exceeds C.int limit")
)

const maxCInt = int64(1<<31 - 1)

// AccessID 获取 AccessID
func AccessID(session int64) (string, error) {
	var result *C.char

	ret := C.AccessID(C.int64_t(session), &result)

	if result != nil {
		defer C.FreeString(result)
	}

	if ret != 0 || result == nil {
		return "", ErrAccessID
	}

	return C.GoString(result), nil
}

// Auth 获取认证信息
func Auth(session int64) (string, string, error) {
	var result1, result2 *C.char

	ret := C.Auth(
		C.int64_t(session),
		&result1,
		&result2,
	)

	if result1 != nil {
		defer C.FreeString(result1)
	}
	if result2 != nil {
		defer C.FreeString(result2)
	}

	if ret != 0 || result1 == nil || result2 == nil {
		return "", "", ErrAuth
	}

	return C.GoString(result1), C.GoString(result2), nil
}

// Check 验证签名
func Check(sign string, data []byte, ak string) (int64, error) {
	if int64(len(data)) > maxCInt {
		return 0, ErrDataTooLarge
	}

	cSign := C.CString(sign)
	cAK := C.CString(ak)

	defer C.free(unsafe.Pointer(cSign))
	defer C.free(unsafe.Pointer(cAK))

	var dataPtr *C.char

	if len(data) > 0 {
		dataPtr = (*C.char)(C.CBytes(data))
		defer C.free(unsafe.Pointer(dataPtr))
	}

	var result C.int64_t

	ret := C.Check(
		cSign,
		dataPtr,
		C.int(len(data)),
		cAK,
		&result,
	)

	if ret != 0 {
		return 0, ErrCheck
	}

	return int64(result), nil
}

// Sign 生成签名
func Sign(data []byte, ak string) (string, error) {
	if int64(len(data)) > maxCInt {
		return "", ErrDataTooLarge
	}

	cAK := C.CString(ak)
	defer C.free(unsafe.Pointer(cAK))

	var dataPtr *C.char

	if len(data) > 0 {
		dataPtr = (*C.char)(C.CBytes(data))
		defer C.free(unsafe.Pointer(dataPtr))
	}

	var result *C.char

	ret := C.Sign(
		dataPtr,
		C.int(len(data)),
		cAK,
		&result,
	)

	if result != nil {
		defer C.FreeString(result)
	}

	if ret != 0 || result == nil {
		return "", ErrSign
	}

	return C.GoString(result), nil
}
