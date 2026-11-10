// @compiles
// CWE-805: memcpy with a length unrelated to the destination.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(char *dst, const char *src, size_t n) {
    char buf[8];
    memcpy(buf, src, n);
    memcpy(dst, buf, sizeof buf);
}
