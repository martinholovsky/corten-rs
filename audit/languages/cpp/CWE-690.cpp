// @compiles
// CWE-690: malloc's result is used without checking for NULL (new would
// throw instead, so the C allocator C++ includes is used).
#include <cstdlib>

void f() {
    int *p = static_cast<int *>(std::malloc(sizeof *p));
    *p = 1;
    std::free(p);
}
