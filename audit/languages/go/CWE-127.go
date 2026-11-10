// @compiles: hatch
// CWE-127: a read lands before the start of a slice's data.
package p

import (
	"unsafe"
)

func f(a []byte, off int) byte {
	return *(*byte)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(a)), -off))
}
