// @rejected: undefined: free
// CWE-763: plain Go has no free; memory is released only by the garbage collector.
package p

func f(p *int) {
	free(p)
}
