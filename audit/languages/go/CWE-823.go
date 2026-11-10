// @compiles: hatch
// CWE-823: a base pointer plus an untrusted offset is read.
package p

import (
	"unsafe"
)

func f(base unsafe.Pointer, off int) byte {
	return *(*byte)(unsafe.Add(base, off))
}
