// @compiles
// CWE-763: frees a pointer to a local object.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(int *p) {
    int x = 0;
    p = &x;
    free(p);
}
