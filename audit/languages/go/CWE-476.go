// @compiles
// CWE-476: dereferences a pointer that may be nil.
package p

type user struct{ name string }

func name(u *user) string {
	return u.name
}

func g() string {
	return name(nil)
}
