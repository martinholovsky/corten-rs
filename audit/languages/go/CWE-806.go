// @compiles: hatch
// CWE-806: a copy uses the source's size for a smaller destination.
package p

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"unsafe"
)

func f(src unsafe.Pointer) {
	small := C.malloc(4)
	C.memcpy(small, src, 64)
	C.free(small)
}
