// @compiles: hatch
// CWE-761: C.free is given a pointer into the middle of a block.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f() {
	p := C.malloc(16)
	C.free(unsafe.Add(p, 4))
}
