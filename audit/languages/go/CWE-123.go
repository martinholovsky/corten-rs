// @compiles: hatch
// CWE-123: a caller-supplied address is written with a caller-supplied value.
package p

import (
	"unsafe"
)

func f(where uintptr, what int) {
	*(*int)(unsafe.Pointer(where)) = what
}
