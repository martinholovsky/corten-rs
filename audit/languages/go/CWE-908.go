// @compiles: hatch
// CWE-908: an uninitialised C buffer is read.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f() byte {
	p := C.malloc(64)
	b := *(*byte)(unsafe.Add(p, 10))
	C.free(p)
	return b
}
