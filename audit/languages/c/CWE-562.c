// @compiles
// CWE-562: returns the address of a stack variable through a copy, which defeats the warning.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int *f(void) {
    int local = 1;
    int *p = &local;
    return p;
}
