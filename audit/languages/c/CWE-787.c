// @compiles
// CWE-787: writes a[i] with no bound check.
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void f(int i, int v) {
    int a[8];
    a[i] = v;
}
