// @compiles
// CWE-468: the offset is scaled twice, once by hand and once by pointer arithmetic.
#include <stddef.h>

int nth(const int *a, size_t i) {
    return *(a + i * sizeof(int));
}
