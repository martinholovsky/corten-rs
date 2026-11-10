// @compiles: hatch
// CWE-120: input is copied into a 16-byte array without a length check.
package p

import (
	"unsafe"
)

func f(in []byte) {
	var buf [16]byte
	for i, b := range in {
		*(*byte)(unsafe.Add(unsafe.Pointer(&buf[0]), i)) = b
	}
}
