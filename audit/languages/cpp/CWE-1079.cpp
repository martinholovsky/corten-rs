// @compiles
// CWE-1079: the base has no virtual destructor, so deleting a Derived through
// a Base pointer is undefined and skips ~Derived.
struct Base { ~Base() {} };
struct Derived : Base {
    char *secret = new char[32];
    ~Derived() { delete[] secret; }
};

void f() {
    Base *b = new Derived;
    delete b;
}
