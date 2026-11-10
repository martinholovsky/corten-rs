// @compiles
// CWE-479: the handler calls printf and malloc, which are not async-signal-safe.
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void handler(int sig) {
    printf("signal %d\n", sig);
    free(malloc(16));
}

void f(void) {
    signal(SIGINT, handler);
}
