// @compiles
// CWE-586: the finalizer function is also called explicitly, so cleanup runs twice.
package p

import (
	"runtime"
	"syscall"
)

type conn struct{ fd int }

func closeConn(c *conn) {
	syscall.Close(c.fd)
}

func open(fd int) *conn {
	c := &conn{fd}
	runtime.SetFinalizer(c, closeConn)
	closeConn(c)
	return c
}
