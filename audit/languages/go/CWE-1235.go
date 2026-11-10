// @compiles
// CWE-1235: ints are boxed into interface values in a hot loop.
package p

func f(n int) []any {
	out := make([]any, 0, n)
	for i := range n {
		out = append(out, i)
	}
	return out
}
