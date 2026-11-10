// @rejected: illegal start of expression
// CWE-787: plain Java has no pointer arithmetic or dereference; the C spelling does not parse.
class P {
    static int f(int[] a, int i) {
        return *(a + i);
    }
}
