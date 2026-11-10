// @compiles
// CWE-127: reads before the buffer's start.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char f(const char *buf, int off) {
    return *(buf - off);
}
