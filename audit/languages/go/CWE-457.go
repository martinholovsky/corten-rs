// @compiles: hatch
// CWE-457: C.malloc returns uninitialised memory, which is read.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f() int {
	p := (*C.int)(C.malloc(16))
	x := int(*p)
	C.free(unsafe.Pointer(p))
	return x
}
