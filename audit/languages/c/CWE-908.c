// @compiles
// CWE-908: reads a malloc'd buffer before writing it.
#include <stdlib.h>

int f(void) {
    int *p = malloc(4 * sizeof *p);
    if (p == NULL) return 0;
    int x = p[2];
    free(p);
    return x;
}
