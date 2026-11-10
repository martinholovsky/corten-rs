// @compiles
// CWE-580: the derived copy constructor does not call the base copy
// constructor, so the base part of the copy is default-constructed.
struct Account {
    int owner = 0;
    Account() = default;
    Account(const Account &o) : owner(o.owner) {}
};

struct Savings : Account {
    int rate = 0;
    Savings() = default;
    Savings(const Savings &o) : rate(o.rate) {}
};
