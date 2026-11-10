// @compiles
// CWE-122: memcpy into a 4-byte heap block with the source's length.
#include <cstring>

void f(const char *s) {
    char *p = new char[4];
    std::memcpy(p, s, std::strlen(s) + 1);
    delete[] p;
}
