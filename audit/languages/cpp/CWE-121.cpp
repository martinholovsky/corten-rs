// @compiles
// CWE-121: memset on a stack buffer with a caller-chosen length.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(size_t n) {
    char buf[16];
    memset(buf, 'A', n);
}
