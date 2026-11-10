// @compiles
// CWE-680: n * sizeof wraps to a small allocation, then n elements are
// written (new[] would throw on the overflow, so the C allocator is used).
#include <cstdlib>
#include <cstddef>

void f(std::size_t n) {
    int *p = static_cast<int *>(std::malloc(n * sizeof *p));
    if (p) { for (std::size_t i = 0; i < n; i++) p[i] = 0; std::free(p); }
}
