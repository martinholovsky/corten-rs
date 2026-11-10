// @compiles: hatch
// CWE-824: a pointer read from uninitialised C memory is dereferenced.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f() int {
	holder := (*unsafe.Pointer)(C.malloc(8))
	return *(*int)(*holder)
}
