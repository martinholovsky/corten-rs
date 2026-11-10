// @compiles
// CWE-364: the signal goroutine clears state the main code still uses.
package p

import (
	"os"
	"os/signal"
	"syscall"
)

var buf []byte

func f() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		<-c
		buf = nil
	}()
	buf = make([]byte, 64)
	buf[0] = 1
}
