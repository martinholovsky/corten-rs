// @compiles
// CWE-786: decrements a pointer below the buffer and writes.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(char *buf) {
    char *p = buf;
    p--;
    *p = 0;
}
