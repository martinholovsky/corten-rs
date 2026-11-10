// @compiles: hatch
// CWE-762: a block from C.malloc is released with munmap instead of free.
package p

/*
#include <stdlib.h>
#include <sys/mman.h>
*/
import "C"

func f() {
	p := C.malloc(4096)
	C.munmap(p, 4096)
}
