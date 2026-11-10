// @compiles: hatch
// CWE-415: the same C block is freed twice.
package p

/*
#include <stdlib.h>
*/
import "C"

func f() {
	p := C.malloc(8)
	C.free(p)
	C.free(p)
}
