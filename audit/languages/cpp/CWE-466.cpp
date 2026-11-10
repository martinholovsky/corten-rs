// @compiles
// CWE-466: returns a pointer beyond the buffer it was derived from.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char *f(char *buf, size_t len) {
    return buf + len + 16;
}
