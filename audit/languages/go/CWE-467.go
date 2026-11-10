// @compiles: hatch
// CWE-467: unsafe.Sizeof of a pointer gives the pointer's size, not the buffer's.
package p

import (
	"unsafe"
)

func f(key *[32]byte) uintptr {
	return unsafe.Sizeof(key)
}
