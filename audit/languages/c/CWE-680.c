// @compiles
// CWE-680: n * sizeof wraps to a small allocation, then n elements are written.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(size_t n) {
    int *p = malloc(n * sizeof *p);
    if (p) { for (size_t i = 0; i < n; i++) p[i] = 0; free(p); }
}
