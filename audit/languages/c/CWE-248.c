// @rejected: 'throw' undeclared (first use in this function)
// CWE-248: C has no throw; the C++ spelling is not C.

void f(void) {
    throw 1;
}
