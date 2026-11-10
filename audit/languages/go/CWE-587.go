// @compiles: hatch
// CWE-587: a hard-coded address is written.
package p

import (
	"unsafe"
)

func f() {
	*(*int)(unsafe.Pointer(uintptr(0x1000))) = 1
}
