// @compiles
// CWE-824: dereferences a pointer that is uninitialised on one path.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int f(int c) {
    int *p;
    if (c) { static int x; p = &x; }
    return *p;
}
