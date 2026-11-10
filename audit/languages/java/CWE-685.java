// @compiles
// CWE-685: String.format is given fewer arguments than its format consumes.
class P {
    static String f(int x) {
        return String.format("%d %d", x);
    }
}
