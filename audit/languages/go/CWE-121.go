// @compiles: hatch
// CWE-121: a stack array is written past its end.
package p

import (
	"unsafe"
)

func f(n int) {
	var buf [16]byte
	for i := 0; i < n; i++ {
		*(*byte)(unsafe.Add(unsafe.Pointer(&buf[0]), i)) = 'A'
	}
}
