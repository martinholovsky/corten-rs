// @compiles: hatch
// CWE-763: C.free is given a pointer C.malloc never returned.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f(b []byte) {
	C.free(unsafe.Pointer(&b[0]))
}
