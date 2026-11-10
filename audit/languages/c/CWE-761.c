// @compiles
// CWE-761: frees a pointer that is not the start of the block.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(void) {
    char *p = malloc(16);
    if (p) free(p + 4);
}
