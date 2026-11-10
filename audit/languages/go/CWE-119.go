// @compiles: hatch
// CWE-119: a loop writes one element past an array through unsafe.Add.
package p

import (
	"unsafe"
)

func f() {
	var a [4]int
	for i := 0; i <= 4; i++ {
		*(*int)(unsafe.Add(unsafe.Pointer(&a[0]), i*8)) = i
	}
}
