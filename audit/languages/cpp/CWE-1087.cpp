// @compiles
// CWE-1087: a class with a virtual method has a non-virtual destructor.
struct Shape {
    virtual double area() const { return 0; }
    ~Shape() {}
};
