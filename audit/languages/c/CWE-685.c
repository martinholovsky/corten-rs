// @compiles
// CWE-685: printf is given fewer arguments than its format consumes.
#include <stdio.h>

void f(int x) {
    printf("%d %d\n", x);
}
