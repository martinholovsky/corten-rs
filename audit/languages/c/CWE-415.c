// @compiles
// CWE-415: the same pointer is freed twice.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(void) {
    char *p = malloc(8);
    free(p);
    free(p);
}
