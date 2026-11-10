// @compiles
// CWE-481: assigns instead of comparing in a boolean condition.
class P {
    static boolean f(boolean admin) {
        if (admin = true) return true;
        return false;
    }
}
