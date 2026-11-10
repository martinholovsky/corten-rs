// @compiles: hatch
// CWE-590: C.free is given the address of a Go variable.
package p

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func f() {
	var x int
	C.free(unsafe.Pointer(&x))
}
