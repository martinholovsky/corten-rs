// @compiles
// CWE-1058: a function called by threads modifies a non-const static.

static int calls;

int handle(void) {
    return ++calls;
}
