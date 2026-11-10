// @compiles
// CWE-828: the handler calls exit(), which runs atexit handlers and flushes stdio.
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void handler(int sig) {
    (void)sig;
    exit(1);
}

void f(void) {
    signal(SIGTERM, handler);
}
