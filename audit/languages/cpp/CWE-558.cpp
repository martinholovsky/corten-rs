// @compiles
// CWE-558: getlogin's static buffer is read from a thread.
#define _POSIX_C_SOURCE 200809L
#include <unistd.h>

const char *who(void) {
    return getlogin();
}
