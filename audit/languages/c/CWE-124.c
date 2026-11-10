// @compiles
// CWE-124: an index that can be negative writes before the buffer.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(int i) {
    char buf[8];
    buf[i - 8] = 0;
}
