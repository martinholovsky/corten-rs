// @compiles
// CWE-831: one handler goroutine serves two signals and is not reentrant.
package p

import (
	"os"
	"os/signal"
	"syscall"
)

var log []string

func f() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGTERM)
	for range 2 {
		go func() {
			for s := range c {
				log = append(log, s.String())
			}
		}()
	}
}
