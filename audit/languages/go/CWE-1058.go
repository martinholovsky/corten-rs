// @compiles
// CWE-1058: a function called from goroutines modifies a package variable.
package p

var calls int

func handle() int {
	calls++
	return calls
}
