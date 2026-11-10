// @compiles: hatch
// CWE-469: addresses from two different objects are subtracted for a length.
package p

import (
	"unsafe"
)

func f(a, b []byte) int {
	return int(uintptr(unsafe.Pointer(&b[0])) - uintptr(unsafe.Pointer(&a[0])))
}
