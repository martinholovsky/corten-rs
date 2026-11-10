// @rejected: invalid operands to binary == (have 'struct rec' and 'struct rec')
// CWE-1097: == is not defined for structs in C.

struct rec { int id; char name[16]; };

int same(struct rec a, struct rec b) {
    return a == b;
}
