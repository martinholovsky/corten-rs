// @compiles
// CWE-908: new int[4] default-initialises, which leaves ints indeterminate,
// and one is read.
int f() {
    int *p = new int[4];
    int x = p[2];
    delete[] p;
    return x;
}
