// @compiles
// CWE-119: the loop bound is off by one and writes a[4].
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(void) {
    int a[4];
    for (int i = 0; i <= 4; i++) a[i] = i;
}
