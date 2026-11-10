// @compiles
// CWE-14: the memset may be removed as a dead store before the buffer goes out of scope.
#include <string.h>

void use_password(void (*consume)(const char *)) {
    char pw[64];
    consume(pw);
    memset(pw, 0, sizeof pw);
}
