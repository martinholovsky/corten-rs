// @compiles
// CWE-1063: a constructor function allocates and initialises an object at load time.
#include <stdlib.h>

static int *table;

__attribute__((constructor)) static void init_table(void) {
    table = malloc(16 * sizeof *table);
}
