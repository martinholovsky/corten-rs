// @compiles: hatch
// CWE-805: C.memcpy is given a length unrelated to the destination.
package p

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"unsafe"
)

func f(src unsafe.Pointer, n int) {
	dst := C.malloc(8)
	C.memcpy(dst, src, C.size_t(n))
	C.free(dst)
}
