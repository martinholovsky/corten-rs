// @compiles
// CWE-470: input names the function that runs.
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stddef.h>

int dispatch(const char *name) {
    void *h = dlopen(NULL, RTLD_NOW);
    int (*fn)(void);
    *(void **)&fn = dlsym(h, name);
    return fn ? fn() : -1;
}
