// @compiles
// CWE-1098: a class owning a raw pointer has a destructor but the default
// (shallow) copy constructor, so two objects delete the same buffer.
class Buf {
public:
    Buf() : data(new char[8]) {}
    ~Buf() { delete[] data; }
    char *data;
};

void f() {
    Buf a;
    Buf b = a;
}
