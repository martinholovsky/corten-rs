// @compiles
// CWE-457: reads a local that was never set.

int f(void) {
    int x;
    return x + 1;
}
