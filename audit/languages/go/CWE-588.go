// @compiles: hatch
// CWE-588: an int is read as a two-field struct.
package p

import (
	"unsafe"
)

type hdr struct{ n, typ int32 }

func f(x *int32) int32 {
	return (*hdr)(unsafe.Pointer(x)).typ
}
