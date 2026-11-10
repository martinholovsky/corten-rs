// @compiles
// CWE-822: dereferences a pointer taken from a message.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int f(const uintptr_t *msg) {
    return *(int *)msg[0];
}
