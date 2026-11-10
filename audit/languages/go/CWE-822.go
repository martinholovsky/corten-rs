// @compiles: hatch
// CWE-822: an address taken from a message is dereferenced.
package p

import (
	"unsafe"
)

func f(msg []uintptr) int {
	return *(*int)(unsafe.Pointer(msg[0]))
}
