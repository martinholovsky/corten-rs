// @compiles
// CWE-586: the destructor is called explicitly, then runs again when the
// object leaves scope, so the buffer is freed twice.
struct Conn {
    char *buf = new char[64];
    ~Conn() { delete[] buf; }
};

void f() {
    Conn c;
    c.~Conn();
}
