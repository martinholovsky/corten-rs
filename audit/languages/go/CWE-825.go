// @compiles: hatch
// CWE-825: a pointer is used after the C block it points into is freed.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

var saved unsafe.Pointer

func f() int {
	p := C.malloc(4)
	saved = p
	C.free(p)
	return int(*(*int32)(saved))
}
