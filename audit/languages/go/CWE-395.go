// @compiles
// CWE-395: recover() is used to detect a nil pointer dereference.
package p

type user struct{ name string }

func name(u *user) (n string) {
	defer func() {
		if recover() != nil {
			n = "anonymous"
		}
	}()
	return u.name
}
