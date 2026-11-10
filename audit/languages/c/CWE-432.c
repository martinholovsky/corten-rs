// @compiles
// CWE-432: the handler stays enabled while shared state is half-updated.
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static int a, b;

static void handler(int sig) {
    (void)sig;
    printf("%d %d\n", a, b);
}

void f(void) {
    signal(SIGINT, handler);
    a = 1;
    b = 1;
}
