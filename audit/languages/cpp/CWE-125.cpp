// @compiles
// CWE-125: reads a[i] with no check against the array's length.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int f(const int *a, int i) {
    return a[i];
}
