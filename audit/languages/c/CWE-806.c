// @compiles
// CWE-806: copies with sizeof the source into a smaller destination.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(const char *src) {
    char small[4];
    char big[64];
    memcpy(big, src, sizeof big);
    memcpy(small, big, sizeof big);
}
