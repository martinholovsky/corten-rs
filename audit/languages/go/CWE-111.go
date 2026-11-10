// @compiles: hatch
// CWE-111: cgo calls C code with none of Go's checks.
package p

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"unsafe"
)

func f(s string) int {
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	return int(C.strlen(cs))
}
