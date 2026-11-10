// @rejected: no match for 'operator==' (operand types are 'const Rec' and 'const Rec')
// CWE-1097: a class has no operator== unless one is declared, so == does
// not fall back to an identity comparison.
struct Rec { int id; char name[16]; };

bool same(const Rec &a, const Rec &b) {
    return a == b;
}
