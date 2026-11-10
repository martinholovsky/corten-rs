// @compiles
// CWE-403: close-on-exec is cleared with a plain syscall before a child is started.
package p

import (
	"syscall"
)

func f(fd uintptr) {
	syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, 0)
}
