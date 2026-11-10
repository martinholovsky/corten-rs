// @compiles
// CWE-476: dereferences a reference that may be null.
class P {
    static int f(String s) {
        return s.length();
    }

    static int g() {
        return f(null);
    }
}
