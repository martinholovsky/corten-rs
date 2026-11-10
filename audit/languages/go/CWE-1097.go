// @compiles
// CWE-1097: stored records are compared by pointer, which is identity.
package p

type rec struct{ id int }

func same(a, b *rec) bool {
	return a == b
}
