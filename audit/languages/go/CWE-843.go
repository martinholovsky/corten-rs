// @compiles: hatch
// CWE-843: a string header is reinterpreted as a slice of ints.
package p

import (
	"unsafe"
)

func f(s *string) []int {
	return *(*[]int)(unsafe.Pointer(s))
}
