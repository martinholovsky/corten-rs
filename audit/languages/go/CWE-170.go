// @compiles: hatch
// CWE-170: a C buffer without a terminator is read with C.GoString.
package p

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"unsafe"
)

func f() string {
	p := (*C.char)(C.malloc(8))
	C.memset(unsafe.Pointer(p), 'a', 8)
	s := C.GoString(p)
	C.free(unsafe.Pointer(p))
	return s
}
