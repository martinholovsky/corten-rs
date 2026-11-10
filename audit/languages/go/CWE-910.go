// @compiles
// CWE-910: a file's descriptor is closed behind its back and the number is reused.
package p

import (
	"os"
	"syscall"
)

func f(a *os.File) (int, error) {
	syscall.Close(int(a.Fd()))
	b, err := os.Open("/etc/hostname")
	if err != nil {
		return 0, err
	}
	defer b.Close()
	return a.Read(make([]byte, 8))
}
