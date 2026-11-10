// @compiles: hatch
// CWE-126: unsafe.Slice builds a slice longer than the data and it is read.
package p

import (
	"unsafe"
)

func f(a []byte) byte {
	b := unsafe.Slice(unsafe.SliceData(a), len(a)+16)
	return b[len(a)+8]
}
