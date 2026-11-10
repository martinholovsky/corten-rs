// @rejected: 'try' undeclared (first use in this function)
// CWE-584: C has no try/finally; the Java spelling is not C.

int f(void) {
    try { return 1; } finally { return 2; }
}
