// @compiles
// CWE-690: malloc's result is used without checking for NULL.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(void) {
    int *p = malloc(sizeof *p);
    *p = 1;
    free(p);
}
