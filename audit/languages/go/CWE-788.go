// @compiles: hatch
// CWE-788: a read lands one element past a slice's end.
package p

import (
	"unsafe"
)

func f(a []byte) byte {
	return *(*byte)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(a)), len(a)))
}
