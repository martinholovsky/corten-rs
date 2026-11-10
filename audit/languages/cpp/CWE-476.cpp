// @compiles
// CWE-476: dereferences a pointer that may be NULL.
#include <stddef.h>

int f(const int *p) {
    return *p;
}

int g(void) {
    return f(NULL);
}
