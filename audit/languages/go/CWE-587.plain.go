// @rejected: cannot use 0x1000 (untyped int constant 4096) as *int value in variable declaration
// CWE-587: an integer constant cannot be used as a pointer.
package p

func f() *int {
	var p *int = 0x1000
	return p
}
