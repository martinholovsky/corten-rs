// @rejected: undefined: gets
// CWE-785: plain Go cannot call a C function; there is no such identifier.
package p

func f() {
	gets(nil)
}
