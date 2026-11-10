// @compiles
// CWE-1042: a non-singleton class keeps per-user state in a static field.
class P {
    static int currentUser;

    void login(int uid) {
        currentUser = uid;
    }
}
