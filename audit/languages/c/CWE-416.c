// @compiles
// CWE-416: the pointer is read after free().
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int f(void) {
    int *p = malloc(sizeof *p);
    if (p == NULL) return -1;
    *p = 42;
    free(p);
    return *p;
}
