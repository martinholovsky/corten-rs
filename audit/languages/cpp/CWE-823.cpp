// @compiles
// CWE-823: dereferences base plus an untrusted offset.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char f(const char *base, long off) {
    return *(base + off);
}
