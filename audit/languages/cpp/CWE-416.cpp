// @compiles
// CWE-416: the pointer is read after delete.
int f() {
    int *p = new int(42);
    delete p;
    return *p;
}
