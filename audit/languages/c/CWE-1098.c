// @compiles
// CWE-1098: a struct copy shares the pointer, and both are freed.
#include <stdlib.h>

struct buf { char *data; };

void f(void) {
    struct buf a = { malloc(8) };
    struct buf b = a;
    free(a.data);
    free(b.data);
}
