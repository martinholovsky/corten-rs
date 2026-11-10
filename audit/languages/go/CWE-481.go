// @rejected: syntax error: cannot use assignment x = 0 as value
// CWE-481: an assignment is not an expression in Go, so it cannot be a condition.
package p

func f(x int) bool {
	if x = 0 {
		return true
	}
	return false
}
