// @compiles: hatch
// CWE-558: libc's getlogin, with its static buffer, is called through cgo.
package p

/*
#include <unistd.h>
*/
import "C"

func f() string {
	return C.GoString(C.getlogin())
}
