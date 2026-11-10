// @compiles: hatch
// CWE-122: a C heap block is written past its end.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f(n int) {
	p := C.malloc(4)
	for i := 0; i < n; i++ {
		*(*byte)(unsafe.Add(p, i)) = 0
	}
	C.free(p)
}
