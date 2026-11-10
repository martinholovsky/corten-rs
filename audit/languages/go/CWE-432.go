// @compiles
// CWE-432: the signal goroutine runs while shared state is half-updated.
package p

import (
	"fmt"
	"os"
	"os/signal"
)

var a, b int

func f() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fmt.Println(a, b)
	}()
	a = 1
	b = 1
}
