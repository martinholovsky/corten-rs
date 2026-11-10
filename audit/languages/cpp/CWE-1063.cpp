// @compiles
// CWE-1063: a static is dynamically initialised by a call at load time,
// standard C++ with no extension.
static int *table = new int[16];
