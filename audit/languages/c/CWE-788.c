// @compiles
// CWE-788: reads one element past the end.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char f(const char *buf, size_t len) {
    return buf[len];
}
