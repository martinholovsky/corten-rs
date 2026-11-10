// @compiles: hatch
// CWE-781: an ioctl-style handler reads through a raw user address.
package p

import (
	"unsafe"
)

type request struct {
	userBuffer uintptr
	length     int
}

func handle(r *request) byte {
	return *(*byte)(unsafe.Pointer(r.userBuffer + uintptr(r.length-1)))
}
