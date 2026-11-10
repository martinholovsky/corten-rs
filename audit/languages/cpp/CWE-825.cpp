// @compiles
// CWE-825: reads through a pointer to an object whose lifetime ended.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int f(void) {
    int *p;
    { int x = 1; p = &x; }
    return *p;
}
