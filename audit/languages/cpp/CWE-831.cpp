// @compiles
// CWE-831: one non-reentrant handler serves two signals.
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static char *state;

static void handler(int sig) {
    (void)sig;
    free(state);
    state = NULL;
}

void f(void) {
    signal(SIGHUP, handler);
    signal(SIGTERM, handler);
}
