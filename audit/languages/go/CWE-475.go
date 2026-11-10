// @compiles: hatch
// CWE-475: unsafe.String is given a length longer than the data.
package p

import (
	"unsafe"
)

func f(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b)+64)
}
