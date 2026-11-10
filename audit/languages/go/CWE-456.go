// @compiles
// CWE-456: a struct field left at its zero value is trusted.
package p

type session struct {
	user    string
	allowed bool
}

func newSession(u string) session {
	return session{user: u}
}
