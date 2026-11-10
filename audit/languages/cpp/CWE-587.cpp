// @compiles
// CWE-587: writes through a hard-coded address.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(void) {
    int *p = (int *)0x1000;
    *p = 1;
}
