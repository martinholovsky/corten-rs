// @compiles: hatch
// CWE-468: an index is scaled twice: by hand, and by the element size again.
package p

import (
	"unsafe"
)

func f(a []int32, i int) int32 {
	return *(*int32)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(a)), i*4*4))
}
