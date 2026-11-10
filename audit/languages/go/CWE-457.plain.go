// @rejected: syntax error: unexpected name x at end of statement
// CWE-457: Go zero-initialises every variable; the C spelling of an uninitialised declaration does not parse.
package p

func f() int {
	int x
	return x
}
