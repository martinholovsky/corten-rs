// @compiles
// CWE-590: frees a stack buffer.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(void) {
    char buf[8];
    char *p = buf;
    free(p);
}
