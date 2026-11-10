// @rejected: 'try' undeclared (first use in this function)
// CWE-396: C has no try/catch; the C++ spelling is not C.

void f(void) {
    try { } catch (...) { }
}
