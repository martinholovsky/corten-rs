// @compiles
// CWE-1056: a variadic function sums whatever it is given.
package p

func sum(xs ...int) int {
	s := 0
	for _, x := range xs {
		s += x
	}
	return s
}
