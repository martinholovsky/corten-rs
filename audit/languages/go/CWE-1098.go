// @compiles
// CWE-1098: a struct copy shares its slice's backing array.
package p

type buf struct{ data []byte }

func f() {
	a := buf{make([]byte, 8)}
	b := a
	b.data[0] = 1
}
