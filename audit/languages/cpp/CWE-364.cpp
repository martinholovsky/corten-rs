// @compiles
// CWE-364: the handler and main code both modify a non-atomic global.
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static char *buf;

static void handler(int sig) {
    (void)sig;
    free(buf);
    buf = NULL;
}

void f(void) {
    signal(SIGTERM, handler);
    buf = static_cast<char *>(malloc(64));
    if (buf) buf[0] = 0;
}
