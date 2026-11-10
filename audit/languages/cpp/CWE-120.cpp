// @compiles
// CWE-120: strcpy into a fixed buffer with no length check.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(const char *input) {
    char buf[8];
    strcpy(buf, input);
}
