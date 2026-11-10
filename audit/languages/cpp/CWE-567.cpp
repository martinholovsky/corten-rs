// @compiles
// CWE-567: two threads increment an unsynchronised global.
#include <threads.h>

static long counter;

static int worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000; i++) counter++;
    return 0;
}

void f(void) {
    thrd_t a, b;
    thrd_create(&a, worker, NULL);
    thrd_create(&b, worker, NULL);
    thrd_join(a, NULL);
    thrd_join(b, NULL);
}
