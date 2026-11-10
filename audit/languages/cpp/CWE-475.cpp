// @compiles
// CWE-475: memcpy with overlapping source and destination is undefined.
#include <string.h>

void f(char *buf) {
    memcpy(buf + 1, buf, 8);
}
