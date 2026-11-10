// @compiles
// CWE-785: realpath into a buffer smaller than PATH_MAX.
#define _XOPEN_SOURCE 700
#include <stdlib.h>

void f(const char *path) {
    char out[64];
    realpath(path, out);
}
