// @rejected: implicit declaration of function 'gets'; did you mean 'fgets'?
// CWE-242: gets() is gone from C17; calling it is an implicit declaration, an error under -pedantic-errors.
#include <stdio.h>

void f(void) {
    char buf[16];
    gets(buf);
}
