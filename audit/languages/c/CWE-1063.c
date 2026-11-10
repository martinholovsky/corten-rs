// @rejected: initializer element is not constant
// CWE-1063: a static initialiser cannot call a function.
#include <stdlib.h>

static int *table = malloc(16 * sizeof *table);
