// @compiles
// CWE-588: an int pointer is read as a struct.

struct hdr { int len; int type; };

int f(int *p) {
    return ((struct hdr *)p)->type;
}
