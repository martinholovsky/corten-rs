// @compiles
// CWE-134: user input passed as printf's format string.
#include <stdio.h>

void f(const char *input) {
    printf(input);
}
