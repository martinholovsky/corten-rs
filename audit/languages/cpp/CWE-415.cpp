// @compiles
// CWE-415: the same pointer is deleted twice.
void f() {
    int *p = new int(1);
    delete p;
    delete p;
}
