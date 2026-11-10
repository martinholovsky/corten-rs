// @compiles: hatch
// CWE-786: a pointer is moved below an array's start and written.
package p

import (
	"unsafe"
)

func f(a []byte) {
	*(*byte)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(a)), -1)) = 0
}
