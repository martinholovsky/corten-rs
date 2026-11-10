// @compiles: hatch
// CWE-466: a function returns a pointer beyond the array it was derived from.
package p

import (
	"unsafe"
)

func f(a []byte) unsafe.Pointer {
	return unsafe.Add(unsafe.Pointer(unsafe.SliceData(a)), len(a)+16)
}
