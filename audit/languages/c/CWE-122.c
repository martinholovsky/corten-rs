// @compiles
// CWE-122: memcpy into a 4-byte heap block with the source's length.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(const char *s) {
    char *p = malloc(4);
    if (p) { memcpy(p, s, strlen(s) + 1); free(p); }
}
