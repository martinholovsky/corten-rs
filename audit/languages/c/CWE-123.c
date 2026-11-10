// @compiles
// CWE-123: a caller-supplied address is written with a caller-supplied value.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(uintptr_t where, int what) {
    *(int *)where = what;
}
