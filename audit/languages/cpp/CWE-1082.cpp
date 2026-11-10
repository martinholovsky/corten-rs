// @compiles
// CWE-1082: the object's own method frees it.
#include <stdlib.h>

struct obj { int refs; };

void obj_release(struct obj *self) {
    if (--self->refs == 0) free(self);
}

int use(struct obj *o) {
    obj_release(o);
    return o->refs;
}
