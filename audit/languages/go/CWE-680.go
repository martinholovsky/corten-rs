// @compiles: hatch
// CWE-680: n * 4 wraps to a small C allocation, and n ints are written.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f(n uint32) {
	p := C.malloc(C.size_t(n * 4))
	for i := uint32(0); i < n; i++ {
		*(*int32)(unsafe.Add(p, i*4)) = 0
	}
	C.free(p)
}
