// @compiles: hatch
// CWE-785: libc's realpath is given a buffer smaller than PATH_MAX through cgo.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f(path string) {
	var out [64]C.char
	cs := C.CString(path)
	C.realpath(cs, &out[0])
	C.free(unsafe.Pointer(cs))
}
