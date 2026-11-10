// @compiles
// CWE-843: a tagged union is read through the wrong member.

struct val { int is_ptr; union { long n; char *p; } u; };

char first(struct val *v) {
    return v->u.p[0];
}
