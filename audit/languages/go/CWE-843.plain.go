// @rejected: cannot convert a (variable of struct type A) to type B
// CWE-843: a conversion between unrelated struct types is rejected; type assertions are checked at run time.
package p

type A struct{ n int }
type B struct{ s string }

func f(a A) B {
	return B(a)
}
