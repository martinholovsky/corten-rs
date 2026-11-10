// @rejected: invalid operation: p + i (mismatched types *int and int)
// CWE-468: plain Go has no pointer arithmetic.
package p

func f(a []int, i int) int {
	p := &a[0]
	return *(p + i)
}
