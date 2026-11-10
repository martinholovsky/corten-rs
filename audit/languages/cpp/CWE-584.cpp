// @rejected: expected 'catch' before 'finally'
// CWE-584: C++ has try/catch but no finally; the Java spelling is not C++.
int f() {
    try { return 1; } finally { return 2; }
}
