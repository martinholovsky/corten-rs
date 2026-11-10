// @compiles
// CWE-456: the variable is set on one path only.

int f(int c) {
    int x;
    if (c) x = 1;
    return x;
}
