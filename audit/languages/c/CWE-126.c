// @compiles
// CWE-126: strlen on an array with no terminator reads past it.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(char *dst) {
    char src[4] = {'a', 'b', 'c', 'd'};
    memcpy(dst, src, strlen(src));
}
