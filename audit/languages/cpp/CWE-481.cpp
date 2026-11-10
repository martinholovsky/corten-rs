// @compiles
// CWE-481: assigns instead of comparing in a condition.

int f(int x) {
    if (x = 0) return 1;
    return 0;
}
