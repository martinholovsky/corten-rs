// @compiles
// CWE-762: a FILE from fopen is released with free() instead of fclose().
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <stdio.h>

void f(void) {
    FILE *fp = fopen("x", "r");
    free(fp);
}
