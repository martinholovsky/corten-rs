// @compiles
// CWE-1042: a non-singleton class keeps shared mutable state in a static
// data member, so every instance writes the same field.
class Session {
public:
    static int current_user;
    void login(int uid) { current_user = uid; }
};
int Session::current_user = 0;
