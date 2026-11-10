// @compiles
// CWE-584: a deferred recover() overwrites the named result and discards the panic.
package p

func f() (ok bool) {
	defer func() {
		recover()
		ok = true
	}()
	panic("authorisation failed")
}
