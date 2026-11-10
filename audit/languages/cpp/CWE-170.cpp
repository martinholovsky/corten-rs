// @compiles
// CWE-170: strncpy fills the buffer without a NUL, and strlen reads past it.
#include <string.h>

size_t f(const char *src) {
    char buf[8];
    strncpy(buf, src, sizeof buf);
    return strlen(buf);
}
