// @rejected: syntax error: cannot use assignment granted = 1 as value
// CWE-483: an if body must be a braced block.
package p

func f(ok bool) int {
	granted := 0
	if ok
		granted = 1
	return granted
}
