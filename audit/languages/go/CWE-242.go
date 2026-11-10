// @compiles: hatch
// CWE-242: gets() is gone from C11 headers; cgo's preamble declares it by hand and calls libc's.
package p

/*
char *gets(char *s);
*/
import "C"

func f() {
	var buf [64]C.char
	C.gets(&buf[0])
}
