// @compiles: hatch
// CWE-787: an array is written at an unchecked index.
package p

import (
	"unsafe"
)

func f(i int, v int) {
	var a [8]int
	*(*int)(unsafe.Add(unsafe.Pointer(&a[0]), i*8)) = v
}
