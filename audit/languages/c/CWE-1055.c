// @rejected: expected identifier or '(' before ':' token
// CWE-1055, multiple inheritance from concrete classes: C has no classes or
// inheritance. The C++ spelling of a class deriving from two concrete classes
// is not C.
struct A { int a; };
struct B { int b; };
struct C : A, B { int c; };
