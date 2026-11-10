// @compiles: hatch
// CWE-124: a write lands before the start of an array.
package p

import (
	"unsafe"
)

func f(i int) {
	var buf [8]byte
	*(*byte)(unsafe.Add(unsafe.Pointer(&buf[0]), i-8)) = 0
}
