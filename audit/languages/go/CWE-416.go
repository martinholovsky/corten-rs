// @compiles: hatch
// CWE-416: a C block is read after it is freed.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f() int {
	p := (*C.int)(C.malloc(4))
	*p = 42
	C.free(unsafe.Pointer(p))
	return int(*p)
}
