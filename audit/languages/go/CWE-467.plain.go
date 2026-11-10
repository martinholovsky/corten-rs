// @rejected: undefined: sizeof
// CWE-467: plain Go has no sizeof; only unsafe.Sizeof exists.
package p

func f(key *[32]byte) int {
	return sizeof(key)
}
