// @compiles: hatch
// CWE-125: a slice's backing array is read at an unchecked index.
package p

import (
	"unsafe"
)

func f(a []int, i int) int {
	return *(*int)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(a)), i*8))
}
