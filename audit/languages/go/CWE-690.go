// @compiles
// CWE-690: a nil map entry is dereferenced unchecked.
package p

type user struct{ name string }

func f(m map[string]*user) string {
	return m["admin"].name
}
